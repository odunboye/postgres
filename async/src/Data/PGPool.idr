module Data.PGPool

import public Data.PGTypes
import public Flux.Async.Core
import Idris2_pg
import Data.IORef
import Data.List
import System
import System.Clock
import System.Concurrency

%default covering

public export
record PoolConfig where
  constructor MkPoolConfig
  connections : Nat
  maxWaiters : Nat
  acquisitionTimeoutMs : Nat

public export
defaultPoolConfig : PoolConfig
defaultPoolConfig = MkPoolConfig 8 128 5000

record State where
  constructor MkState
  accepting : Bool
  allocated : Nat
  opening : Bool
  idle : List DB
  queue : List Integer
  nextTicket : Integer

||| Connections never escape through the pool API except as scoped callback
||| arguments. Callbacks must not retain or fork work using their DB handle.
export
record Pool where
  constructor MkPool
  mutex : Mutex
  available : Condition
  state : IORef State
  limits : PoolConfig
  database : PGConfig

mutate : Pool -> (State -> (State, a)) -> IO a
mutate pool f = do
  mutexAcquire pool.mutex
  (state, result) <- map f (readIORef pool.state)
  writeIORef pool.state state
  mutexRelease pool.mutex
  pure result

nowMs : IO Integer
nowMs = do
  t <- clockTime Monotonic
  pure (seconds t * 1000 + nanoseconds t `div` 1000000)

||| Creates a lazy, bounded pool. Missing transport deadlines get finite
||| defaults: five seconds to connect and thirty seconds per DB operation.
export
newPool : PoolConfig -> PGConfig -> IO (Either PGError Pool)
newPool limits config =
  if limits.connections == 0 || limits.maxWaiters == 0 || limits.acquisitionTimeoutMs == 0
    then pure (Left (ConnectionError "pool limits must be positive"))
    else do
      let config = { connectTimeoutMs := Just (maybe 5000 id config.connectTimeoutMs),
                     readTimeoutMs := Just (maybe 30000 id config.readTimeoutMs) } config
      pool <- MkPool <$> makeMutex <*> makeCondition <*> newIORef (MkState True 0 False [] [] 0)
                     <*> pure limits <*> pure config
      pure (Right pool)

joinQueue : Pool -> IO (Either PGError Integer)
joinQueue pool = mutate pool $ \state =>
  if not state.accepting then (state, Left (ConnectionError "pool is closed"))
  else if length state.queue >= pool.limits.maxWaiters
    then (state, Left (ConnectionError "pool acquisition queue is full"))
    else let ticket = state.nextTicket in
      ({ queue := state.queue ++ [ticket], nextTicket := ticket + 1 } state, Right ticket)

leaveQueue : Pool -> Integer -> IO ()
leaveQueue pool ticket = mutate pool $ \state =>
  ({ queue := filter (/= ticket) state.queue } state, ())

data Available = Wait | Create | Reuse DB | Closed

tryLease : Pool -> Integer -> IO Available
tryLease pool ticket = mutate pool $ \state =>
  if not state.accepting then (state, Closed) else case state.queue of
    [] => (state, Wait)
    first :: rest => if first /= ticket then (state, Wait) else case state.idle of
      db :: idle => ({ idle := idle, queue := rest } state, Reuse db)
      [] => if state.allocated < pool.limits.connections && not state.opening
        then ({ allocated := S state.allocated, opening := True, queue := rest } state, Create)
        else (state, Wait)

releaseSlot : Pool -> IO ()
releaseSlot pool = mutate pool $ \state => ({ allocated := state.allocated `minus` 1 } state, ())

-- Pure SCRAM hashing allocates heavily on Chez. Serializing cold connection
-- setup avoids a GC contention cliff. Other borrowers remain in the FIFO
-- queue, where they can reuse returned connections, rather than reserving
-- slots and spending their acquisition deadline blocked on an auth mutex.
openConnection : Pool -> Integer -> IO (Either PGError DB)
openConnection pool deadline = do
  now <- nowMs
  result <- if now >= deadline
    then pure (Left (ConnectionError "pool acquisition timed out"))
    else do
      let remaining = cast {to = Nat} (deadline - now)
      let config = { connectTimeoutMs := Just (min remaining (maybe remaining id pool.database.connectTimeoutMs)) } pool.database
      connectDB config
  mutate pool (\state => ({ opening := False } state, ()))
  pure result

acquireUntil : Pool -> Integer -> Integer -> Task es (Either PGError DB)
acquireUntil pool ticket deadline = do
  now <- liftIO nowMs
  if now >= deadline then pure (Left (ConnectionError "pool acquisition timed out")) else do
    available <- liftIO (tryLease pool ticket)
    case available of
      Closed => pure (Left (ConnectionError "pool is closed"))
      Reuse db => pure (Right db)
      Wait => Interruptible (sleep 1) >> acquireUntil pool ticket deadline
      Create => do
        -- Acquisition runs masked: retain the result and slot even when a
        -- cancel request arrives while the native connection is being opened.
        result <- blocking (openConnection pool deadline)
        case result of
          Left _ => do
            liftIO $ mutate pool (\state =>
              ({ opening := False, allocated := state.allocated `minus` 1 } state, ()))
            pure (Left (ConnectionError "blocking IO queue is full or closed"))
          Right (Left err) => liftIO (releaseSlot pool) $> Left err
          Right (Right db) => do
            now <- liftIO nowMs
            if now >= deadline
              then liftIO (closeDB db >> releaseSlot pool) $> Left (ConnectionError "pool acquisition timed out")
              else pure (Right db)

acquire : Pool -> Task es (Either PGError DB)
acquire pool = bracket
  (liftIO (joinQueue pool))
  (\result => case result of Left _ => pure (); Right ticket => liftIO (leaveQueue pool ticket))
  (\result => case result of
    Left err => pure (Left err)
    Right ticket => do
      deadline <- map (+ cast pool.limits.acquisitionTimeoutMs) (liftIO nowMs)
      acquireUntil pool ticket deadline)

returnConnection : Pool -> DB -> IO ()
returnConnection pool db = do
  unusable <- readIORef db.unusable
  transaction <- readIORef db.txState
  -- Discard transactions left open by a callback; closing rolls them back.
  let healthy = not unusable && case transaction of Just Idle => True; _ => False
  retained <- mutate pool $ \state =>
    if healthy && state.accepting
      then ({ idle := db :: state.idle } state, True)
      else (state, False)
  -- Keep the slot counted until the native close has completed. Otherwise
  -- poolClosed could report reclamation while a returning lease still owns IO.
  unless retained (closeDB db >> releaseSlot pool)

||| Hold one exclusive DB for the entire synchronous callback, including
||| transactions across repositories. Cancellation joins the worker before
||| returning or discarding the connection. No query thread is abandoned.
export
withConnection : Pool -> (DB -> IO (Either PGError a)) -> Task es (Either PGError a)
withConnection pool callback = bracket
  (acquire pool)
  (\result => case result of Left _ => pure (); Right db => liftIO (returnConnection pool db))
  (\result => case result of
    Left err => pure (Left err)
    Right db => do
      result <- blocking (callback db)
      pure (case result of
        Left _ => Left (ConnectionError "blocking IO queue is full or closed")
        Right value => value))

||| Stop new leases and close idle connections. In-flight leases close when
||| their owning callback has finished. This operation is idempotent.
export
closePool : Pool -> IO ()
closePool pool = do
  idle <- mutate pool $ \state =>
    ({ accepting := False, idle := [] } state, state.idle)
  traverse_ closeDB idle
  mutate pool (\state => ({ allocated := state.allocated `minus` length idle } state, ()))

export
poolClosed : Pool -> IO Bool
poolClosed pool = mutate pool $ \state => (state, not state.accepting && state.allocated == 0)

-- Scheme condition waits release the thread for collection. Repeated native
-- usleep calls here would delay SCRAM allocation on other workers.
waitForSlot : Pool -> IO ()
waitForSlot pool = do
  mutexAcquire pool.mutex
  conditionWaitTimeout pool.available pool.mutex 1000
  mutexRelease pool.mutex

acquireIO : Pool -> Integer -> Integer -> IO (Either PGError DB)
acquireIO pool ticket deadline = do
  now <- nowMs
  if now >= deadline then pure (Left (ConnectionError "pool acquisition timed out")) else do
    available <- tryLease pool ticket
    case available of
      Closed => pure (Left (ConnectionError "pool is closed"))
      Reuse db => pure (Right db)
      Wait => waitForSlot pool >> acquireIO pool ticket deadline
      Create => do
        result <- openConnection pool deadline
        case result of
          Left err => releaseSlot pool $> Left err
          Right db => do
            now <- nowMs
            if now >= deadline
              then closeDB db >> releaseSlot pool $> Left (ConnectionError "pool acquisition timed out")
              else pure (Right db)

||| Synchronous scoped borrowing for IO repositories. Call this through
||| blocking (or Flux.DB.PG.dbIO) from an event loop. The same FIFO queue and
||| connection limits are shared with withConnection's task interface.
export
withConnectionIO : Pool -> (DB -> IO (Either PGError a)) -> IO (Either PGError a)
withConnectionIO pool callback = do
  deadline <- map (+ cast pool.limits.acquisitionTimeoutMs) nowMs
  Right ticket <- joinQueue pool | Left err => pure (Left err)
  result <- acquireIO pool ticket deadline
  leaveQueue pool ticket
  case result of
    Left err => pure (Left err)
    Right db => do
      result <- callback db
      returnConnection pool db
      pure result
