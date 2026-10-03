module TLSIdentityTests

import Idris2_pg
import Data.PGTypes
import Data.PGValue
import Helper
import Network.Deadline
import System
import Data.IORef
import Data.List
import Data.Maybe
import Data.String

%default covering

-- Standalone equivalent of an application's own PGSSLMODE/PGSSLROOTCERT
-- loading - only explicit verified TLS or explicit plaintext is supported.
-- Never treat libpq's weaker prefer/allow/require modes as permission to
-- skip identity.
appConfig : IO PGConfig
appConfig = do
  host <- fromMaybe "127.0.0.1" <$> getEnv "PGHOST"
  port <- fromMaybe 5432 . (>>= parsePositive) <$> getEnv "PGPORT"
  user <- fromMaybe "testuser" <$> getEnv "PGUSER"
  password <- fromMaybe "testpass" <$> getEnv "PGPASSWORD"
  database <- fromMaybe "testdb" <$> getEnv "PGDATABASE"
  mode <- getEnv "PGSSLMODE"
  ca <- getEnv "PGSSLROOTCERT"
  let cfg = mkPGConfig host port user password database
  pure $ case mode of
    Just "verify-full" => { useTLS := True, tlsCAFile := ca } cfg
    _ => cfg

main : IO ()
main = do
  Just host <- getEnv "PG_TLS_HOST" | Nothing => exitFailure
  Just port <- getEnv "PG_TLS_PORT" | Nothing => exitFailure
  Just mode <- getEnv "PG_TLS_MODE" | Nothing => exitFailure
  ca <- getEnv "PG_TLS_CA"
  let config : PGConfig
      config = { useTLS := True, tlsCAFile := ca,
                 connectTimeoutMs := Just 5000, readTimeoutMs := Just 500 } $
        mkPGConfig host (cast port) "testuser" "testpass" "testdb"
  case mode of
    "appconfig" => do
      appCfg <- appConfig
      unless appCfg.useTLS exitFailure
      Right db <- connectDB ({ connectTimeoutMs := Just 5000, readTimeoutMs := Just 500 } appCfg)
        | Left err => putStrLn (displayError err) >> exitFailure
      Right [_] <- queryRows db "SELECT 1" [] | _ => closeDB db >> exitFailure
      closeDB db
      putStrLn "PASS application PGSSLMODE verify-full and CA configuration"
    "database" => do
      Right db <- connectDB config | Left err => putStrLn (displayError err) >> exitFailure
      Right [row] <- queryRows db "SELECT ssl, version FROM pg_stat_ssl WHERE pid=pg_backend_pid()" []
        | _ => closeDB db >> exitFailure
      unless (columnByName row "ssl" == Just (Just "t") && columnByName row "version" == Just (Just "TLSv1.3")) $
        closeDB db >> exitFailure
      let payload = concat (replicate 4000 "λabc")
      Right [roundtrip] <- queryRows db "SELECT $1::text AS value" [Just payload]
        | _ => closeDB db >> exitFailure
      unless (columnByName roundtrip "value" == Just (Just payload)) $ closeDB db >> exitFailure
      putStrLn "PASS verified TLS 1.3, SCRAM and large exact payload"
      let slowFrame = encode (Parse "" "SELECT pg_sleep(2)" [])
                        ++ encode (Bind "" "" [] False)
                        ++ encode (Describe 'P' "") ++ encode (Execute "" 0) ++ encode Sync
      Right () <- pgSend (conn db) slowFrame | Left _ => closeDB db >> exitFailure
      badCancel <- cancelQuery ({ cfg := { tlsCAFile := Just "/nonexistent/postgres-ca.pem" } config } db)
      case badCancel of
        Left _ => pure ()
        Right _ => closeDB db >> exitFailure
      Right () <- cancelQuery db | Left err => putStrLn (displayError err) >> closeDB db >> exitFailure
      Right [cancelled] <- handleQueryResponses db | _ => closeDB db >> exitFailure
      unless (any (\e => code e == Just "57014") (errors cancelled)) $ closeDB db >> exitFailure
      putStrLn "PASS cancellation connection revalidates TLS identity and closes"
      result <- queryRows db "SELECT pg_sleep(2)" []
      case result of
        Left (ConnectionError _) => pure ()
        _ => closeDB db >> exitFailure
      poisoned <- readIORef db.unusable
      unless poisoned exitFailure
      again <- queryRows db "SELECT 1" []
      case again of
        Left (ConnectionError _) => pure ()
        _ => closeDB db >> exitFailure
      closeDB db
      closeDB db
      putStrLn "PASS verified TLS read deadline, poisoning and repeated close"
    _ => do
      (expired, result) <- withDeadline 500 (connectPG host (cast port) True ca)
      case result of
        Right connection => do
          closePGConnection connection
          if mode == "ok" && not expired then putStrLn "PASS identity accepted" else exitFailure
        Left error => do
          putStrLn error
          if mode == "reject" && not expired then putStrLn "PASS identity rejected"
            else if mode == "timeout" && expired then putStrLn "PASS TLS deadline joined"
            else exitFailure
