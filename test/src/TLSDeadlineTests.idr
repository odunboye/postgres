module TLSDeadlineTests

import Idris2_pg
import Data.PGTypes
import Data.PGValue
import System
import Data.IORef

%default covering

main : IO ()
main = do
  Just port <- getEnv "PG_TEST_PORT" | Nothing => putStrLn "PG_TEST_PORT required" >> exitFailure
  Just ca <- getEnv "PG_TEST_CA_FILE" | Nothing => putStrLn "PG_TEST_CA_FILE required" >> exitFailure
  let cfg : PGConfig
      cfg = { useTLS := True, tlsCAFile := Just ca, connectTimeoutMs := Just 30000, readTimeoutMs := Just 500 } $
        mkPGConfig "127.0.0.1" (cast port) "testuser" "testpass" "testdb"
  Right db <- connectDB cfg | Left err => putStrLn (displayError err) >> exitFailure
  Right _ <- queryRows db "SELECT 42" [] | Left err => putStrLn (displayError err) >> closeDB db >> exitFailure
  putStrLn "PASS TLS handshake and query over deadline-aware transport"
  result <- queryRows db "SELECT pg_sleep(2)" []
  case result of
    Left (ConnectionError _) => pure ()
    _ => putStrLn "FAIL TLS read timeout" >> closeDB db >> exitFailure
  invalid <- readIORef db.unusable
  unless invalid (putStrLn "FAIL timed-out TLS connection reusable" >> exitFailure)
  result <- queryRows db "SELECT 1" []
  case result of
    Left (ConnectionError _) => putStrLn "PASS TLS timeout poisons connection and rejects reuse"
    _ => putStrLn "FAIL TLS connection reused" >> closeDB db >> exitFailure
  closeDB db
  closeDB db
