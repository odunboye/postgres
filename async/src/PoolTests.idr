module PoolTests

import Data.PGPool
import Idris2_pg
import Data.PGValue
import Async.Runner
import Data.IORef
import Data.List
import System
import System.Concurrency
import System.File

%default covering

check : IORef Nat -> String -> Bool -> IO ()
check failures label ok = do
  putStrLn ((if ok then "PASS " else "FAIL ") ++ label)
  fflush stdout
  unless ok (modifyIORef failures S)

run : Task [] a -> IO a
run action = do
  Right (Succeeded result) <- runTask action | _ => putStrLn "FAIL runtime execution" >> exitFailure
  pure result

pid : DB -> IO (Either PGError String)
pid db = do
  Right [row] <- queryRows db "SELECT pg_backend_pid()::text AS pid" []
    | Left err => pure (Left err)
    | Right _ => pure (Left (ProtocolError "missing backend PID"))
  pure (case getText row "pid" of Left err => Left (ProtocolError err); Right n => Right n)

borrow : Pool -> Bool -> (DB -> IO (Either PGError String)) -> Task [] (Either PGError String)
borrow pool False callback = withConnection pool callback
borrow pool True callback = do
  Right result <- blocking (withConnectionIO pool callback)
    | Left _ => pure (Left (ConnectionError "worker queue unavailable"))
  pure result

parallel : Pool -> Bool -> IORef Nat -> IORef Nat -> Mutex -> Task [] (List (Outcome [] (Either PGError String)))
parallel pool viaIO active peak lock = do
  arrived <- liftIO (newIORef 0)
  gate <- liftIO (newIORef False)
  ready <- liftIO makeCondition
  children <- traverse (\_ => spawn $ the (Task [] (Either PGError String)) $
    borrow pool viaIO $ \db => do
      mutexAcquire lock
      n <- readIORef active
      writeIORef active (S n)
      modifyIORef peak (max (S n))
      modifyIORef arrived S
      awaitGate gate ready lock
      mutexRelease lock
      result <- pid db
      usleep 20000
      mutexAcquire lock
      modifyIORef active (\n => n `minus` 1)
      mutexRelease lock
      pure result) (replicate 12 ())
  _ <- race (waitTwo arrived lock) (sleep 8000)
  liftIO $ do
    mutexAcquire lock
    writeIORef gate True
    conditionBroadcast ready
    mutexRelease lock
  traverse join children
  where
    awaitGate : IORef Bool -> Condition -> Mutex -> IO ()
    awaitGate gate ready lock = do
      opened <- readIORef gate
      unless opened (conditionWait ready lock >> awaitGate gate ready lock)

    waitTwo : IORef Nat -> Mutex -> Task [] ()
    waitTwo arrived lock = do
      n <- liftIO $ do
        mutexAcquire lock
        n <- readIORef arrived
        mutexRelease lock
        pure n
      unless (n >= 2) (sleep 1 >> waitTwo arrived lock)

main : IO ()
main = do
  failures <- newIORef 0
  let cfg = mkPGConfig "127.0.0.1" 5432 "testuser" "testpass" "testdb"
  putStrLn "Starting initial connection"
  fflush stdout
  Right initial <- connectDB ({ connectTimeoutMs := Just 2000 } cfg)
    | Left err => putStrLn ("FAIL pool test database: " ++ displayError err) >> exitFailure
  putStrLn "Initial connection succeeded"
  fflush stdout
  closeDB initial
  Right pool <- newPool (MkPoolConfig 2 128 5000) cfg | Left err => putStrLn (displayError err) >> exitFailure
  active <- newIORef 0
  peak <- newIORef 0
  lock <- makeMutex
  putStrLn "Starting concurrent callbacks"
  fflush stdout
  results <- run (parallel pool False active peak lock)
  count <- readIORef peak
  let ids = mapMaybe (\result => case result of Succeeded (Right n) => Just n; _ => Nothing) results
  traverse_ (\result => case result of Succeeded (Left err) => putStrLn (displayError err); Canceled => putStrLn "child canceled"; _ => pure ()) results
  check failures "all concurrent pool operations complete" (length ids == 12)
  check failures "pool bounds exclusive concurrent callbacks" (count == 2)
  check failures "pool reuses only its two backend connections" (length (nub ids) == 2)

  closePool pool
  closed <- poolClosed pool
  check failures "closing idle pool releases all connections" closed
  rejected <- run (withConnection pool pid)
  check failures "closed pool rejects new callbacks" (case rejected of Left _ => True; _ => False)

  Right ioPool <- newPool (MkPoolConfig 2 128 5000) cfg | Left _ => exitFailure
  writeIORef active 0
  writeIORef peak 0
  results <- run (parallel ioPool True active peak lock)
  count <- readIORef peak
  let ioIds = mapMaybe (\result => case result of Succeeded (Right n) => Just n; _ => Nothing) results
  check failures "IO repository callbacks complete through bounded workers" (length ioIds == 12)
  check failures "IO repository leases preserve exclusivity and reuse" (count == 2 && length (nub ioIds) == 2)
  closePool ioPool

  Right pool <- newPool (MkPoolConfig 1 2 5000) ({ readTimeoutMs := Just 100 } cfg)
    | Left _ => exitFailure
  before <- run (withConnection pool pid)
  timed <- run (withConnection pool (\db => queryRows db "SELECT pg_sleep(1)" []))
  after <- run (withConnection pool pid)
  check failures "slow query returns a timeout" (case timed of Left (ConnectionError _) => True; _ => False)
  check failures "timed-out connection is replaced" (case (before, after) of (Right a, Right b) => a /= b; _ => False)

  transaction <- run (withConnection pool (\db => execCommand db "BEGIN" []))
  afterTransaction <- run (withConnection pool pid)
  -- The connection on which BEGIN was left open must have been discarded.
  check failures "open transaction is discarded before reuse" (case (after, afterTransaction) of (Right a, Right b) => a /= b; _ => False)
  closePool pool

  Right pool <- newPool (MkPoolConfig 1 2 5000) cfg | Left _ => exitFailure
  started <- makeChannel
  finished <- newIORef False
  run $ the (Task [] ()) $ do
    child <- spawn $ the (Task [] (Either PGError ())) $ withConnection pool $ \_ => do
      channelPut started ()
      usleep 40000
      writeIORef finished True
      pure (Right ())
    ready <- race (awaitStart started) (sleep 3000)
    cancel child
  joined <- readIORef finished
  check failures "cancellation joins callback before returning its lease" joined
  reused <- run (withConnection pool pid)
  check failures "pool remains usable after joined cancellation" (case reused of Right _ => True; _ => False)
  closePool pool

  -- Keep the only lease occupied while other tasks exercise the bounded FIFO.
  Right pool <- newPool (MkPoolConfig 1 1 5000) cfg | Left _ => exitFailure
  _ <- run (withConnection pool pid)
  gate <- newIORef False
  gateLock <- makeMutex
  gateCondition <- makeCondition
  acquired <- makeChannel
  waitingResults <- run $ the (Task [] (List (Outcome [] (Either PGError String)))) $ do
    holder <- spawn $ the (Task [] (Either PGError String)) $ withConnection pool $ \db => do
      channelPut acquired ()
      mutexAcquire gateLock
      waitGate gate gateCondition gateLock
      mutexRelease gateLock
      pid db
    guarantee
      (do
        awaitStart acquired
        waiters <- traverse (\_ => spawn $ the (Task [] (Either PGError String)) $
          withConnection pool pid) (replicate 7 ())
        traverse join waiters)
      (liftIO $ do
        mutexAcquire gateLock
        writeIORef gate True
        conditionBroadcast gateCondition
        mutexRelease gateLock)
  let full = filter (\result => case result of
        Succeeded (Left (ConnectionError "pool acquisition queue is full")) => True
        _ => False) waitingResults
  let timedOut = filter (\result => case result of
        Succeeded (Left (ConnectionError "pool acquisition timed out")) => True
        _ => False) waitingResults
  check failures "full pool queue rejects excess waiters" (length full == 6)
  check failures "admitted pool waiter expires without taking an occupied lease" (length timedOut == 1)
  afterWait <- run (withConnection pool pid)
  check failures "expired waiter leaves pool usable" (case afterWait of Right _ => True; _ => False)
  closePool pool
  n <- readIORef failures
  if n == 0 then putStrLn "All pool checks passed" else exitFailure
  where
    waitGate : IORef Bool -> Condition -> Mutex -> IO ()
    waitGate gate condition lock = do
      opened <- readIORef gate
      unless opened (conditionWait condition lock >> waitGate gate condition lock)

    awaitStart : Channel () -> Task [] ()
    awaitStart channel = do
      result <- liftIO (channelGetNonBlocking channel)
      case result of Just () => pure (); Nothing => sleep 1 >> awaitStart channel
