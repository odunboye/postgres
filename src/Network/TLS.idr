||| Authenticated TLS 1.3 through OpenSSL 3. Chain validation, SAN DNS/IP
||| identity, CertificateVerify and Finished are mandatory. No insecure mode.
||| Native BIO I/O uses the same thread-owned deadlines as plaintext transport.
module Network.TLS

import Network.Socket
import Data.Buffer
import Data.IORef
import Data.List
import Data.Maybe

%default covering

export
record TLSSession where
  constructor MkTLSSession
  handle : IORef (Maybe AnyPtr)

%foreign "C:pg_tls_new,libidris2_pg_transport"
primNew : Int -> String -> String -> PrimIO AnyPtr
%foreign "C__collect_safe:pg_tls_handshake,libidris2_pg_transport"
primHandshake : AnyPtr -> PrimIO Int
%foreign "C:pg_tls_free,libidris2_pg_transport"
primFree : AnyPtr -> PrimIO ()
%foreign "C:pg_tls_error,libidris2_pg_transport"
primError : AnyPtr -> PrimIO String
%foreign "C__collect_safe:pg_tls_send,libidris2_pg_transport"
primSend : AnyPtr -> Buffer -> Int -> PrimIO Int
%foreign "C__collect_safe:pg_tls_receive,libidris2_pg_transport"
primReceive : AnyPtr -> Buffer -> Int -> PrimIO Int
%foreign "scheme:(lambda (buffer) (lock-object buffer))"
primLock : Buffer -> PrimIO ()
%foreign "scheme:(lambda (buffer) (unlock-object buffer))"
primUnlock : Buffer -> PrimIO ()

||| Nothing uses OpenSSL's system trust paths; Just uses only that PEM CA file.
||| Identity is always the configured connection host, not a separate override.
export
tlsClientHandshake : Socket -> String -> Maybe String -> IO (Either String TLSSession)
tlsClientHandshake socket host caFile = do
  if host == "" || elem '\0' (unpack host) ||
     maybe False (\p => p == "" || elem '\0' (unpack p)) caFile
    then pure (Left "TLS: invalid host or CA file")
    else do
      pointer <- primIO (primNew socket.descriptor host (fromMaybe "" caFile))
      if prim__nullAnyPtr pointer /= 0 then pure (Left "TLS allocation failed") else do
        result <- primIO (primHandshake pointer)
        case result of
          0 => do
            ref <- newIORef (Just pointer)
            pure (Right (MkTLSSession ref))
          _ => do
            err <- primIO (primError pointer)
            primIO (primFree pointer)
            pure (Left err)

||| Frees TLS state without waiting for peer shutdown; the caller owns the fd.
||| Shared session references make repeated cleanup a no-op.
export
tlsClose : TLSSession -> IO ()
tlsClose session = do
  pointer <- readIORef session.handle
  writeIORef session.handle Nothing
  case pointer of
    Nothing => pure ()
    Just p => primIO (primFree p)

public export
maxPlaintextPerRecord : Nat
maxPlaintextPerRecord = 16384

export
chunksOf : (n : Nat) -> List a -> List (List a)
chunksOf n [] = []
chunksOf n xs = let (chunk, rest) = splitAt n xs in chunk :: chunksOf n rest

fill : Buffer -> Int -> List Bits8 -> IO ()
fill _ _ [] = pure ()
fill buffer i (b :: bs) = setBits8 buffer i b >> fill buffer (i + 1) bs

readBytes : Buffer -> Int -> Int -> IO (List Bits8)
readBytes buffer i n = if i >= n then pure [] else do
  b <- getBits8 buffer i
  bs <- readBytes buffer (i + 1) n
  pure (b :: bs)

export
tlsSend : TLSSession -> List Bits8 -> IO (Either String ())
tlsSend session bytes = do
  Just pointer <- readIORef session.handle | Nothing => pure (Left "TLS session is closed")
  go pointer bytes
  where
    go : AnyPtr -> List Bits8 -> IO (Either String ())
    go _ [] = pure (Right ())
    go p remaining = do
      let chunk = take maxPlaintextPerRecord remaining
      let size = cast (length chunk)
      Just buffer <- newBuffer size | Nothing => pure (Left "TLS send allocation failed")
      fill buffer 0 chunk
      primIO (primLock buffer)
      count <- primIO (primSend p buffer size)
      primIO (primUnlock buffer)
      if count <= 0 then Left <$> primIO (primError p)
        else go p (drop (cast count) remaining)

export
tlsReceiveExact : TLSSession -> Int -> IO (Either String (List Bits8))
tlsReceiveExact session n = do
  Just pointer <- readIORef session.handle | Nothing => pure (Left "TLS session is closed")
  go pointer n []
  where
    go : AnyPtr -> Int -> List (List Bits8) -> IO (Either String (List Bits8))
    go p remaining chunks = if remaining <= 0 then pure (Right (concat (reverse chunks))) else do
      let size = min remaining 65536
      Just buffer <- newBuffer size | Nothing => pure (Left "TLS receive allocation failed")
      primIO (primLock buffer)
      count <- primIO (primReceive p buffer size)
      primIO (primUnlock buffer)
      if count <= 0 then Left <$> primIO (primError p) else do
        bytes <- readBytes buffer 0 count
        go p (remaining - count) (bytes :: chunks)
