module Helper

import Network.Socket
import Network.Deadline
import Data.Bits
import Data.IORef
import Data.List
import Data.Maybe
import Data.PGTypes
import public Data.Utf8
import Network.Core
import Network.RawSocket
import Network.TLS
import Crypto.MD5
import Crypto.SCRAM
import Derive.Prelude


data SocketState = Connected | UnKnown

getSock : IO (Either SocketError Socket)
getSock = socket AF_INET Stream 0 

export
getConnection :  Socket -> SocketAddress -> Port ->  IO (Maybe Socket)
getConnection s addr p= do
         res <- connectSocket s (show addr) p
         case res of 
              0 => do 
                pure (Just (s))
              _ => do
                pure Nothing

public export
toInt : Vect 4 Bits8 ->  Int
toInt [x, y, z, w] = ((cast x) `shiftL` 24)
  .|. ((cast y) `shiftL` 16)
  .|. ((cast z) `shiftL` 8)
  .|. cast w

-- A defensive cap, not something the wire protocol itself mandates: without
-- it a malicious/compromised server could declare an arbitrarily large
-- message length and force this client to buffer that many bytes.
public export
maxFrameBodySize : Int
maxFrameBodySize = 1073741824  -- 1 GiB

||| Validates a message's declared length (the 4-byte length field, which
||| includes itself) before it drives a read, returning the payload size to
||| actually read. Rejects a length smaller than the 4-byte prefix itself
||| (which would otherwise go negative and desync the frame boundary) and a
||| payload larger than `maxFrameBodySize`.
public export
validateFrameLength : Int -> Either String Int
validateFrameLength msgLen =
  if msgLen < 4
     then Left "Protocol error: message length field is smaller than the 4-byte length prefix itself"
     else let payloadLen = msgLen - 4
          in if payloadLen > maxFrameBodySize
                then Left ("Protocol error: server-declared message length " ++ show msgLen
                            ++ " exceeds the " ++ show maxFrameBodySize ++ "-byte limit")
                else Right payloadLen

-- Encode/decode 16-bit and 32-bit integers (big endian)
public export
encodeInt16 : Int -> List Bits8
encodeInt16 n =
  [ fromInteger (cast((shiftR n 8) .&. 0xFF))
  , fromInteger (cast(n .&. 0xFF))
  ]

public export
encodeInt32 : Int -> List Bits8
encodeInt32 n =
  [ fromInteger (cast((shiftR n 24) .&. 0xFF))
  , fromInteger (cast((shiftR n 16) .&. 0xFF))
  , fromInteger (cast((shiftR n 8) .&. 0xFF))
  , fromInteger (cast(n .&. 0xFF))
  ]

public export
-- `Int` is 64-bit here, so the raw accumulated value is always non-negative
-- and must be re-interpreted as a signed 16/32-bit two's-complement value
-- (Postgres uses negative Int16/Int32 wire values for real, e.g. a NULL
-- Bind parameter or DataRow column is length -1, and a variable-length
-- column's RowDescription typeSize is -1) or values like that decode wrong
-- (previously: -1 came back as 65535 / 4294967295).
decodeInt16 : List Bits8 -> Either String (Int, List Bits8)
decodeInt16 (b1 :: b2 :: rest) =
  let raw : Int
      raw = shiftL (cast b1) 8 + cast b2
      signed : Int
      signed = if raw >= 0x8000 then raw - 0x10000 else raw
  in Right (signed, rest)
decodeInt16 _ = Left "decodeInt16: insufficient bytes"

public export
decodeInt32 : List Bits8 -> Either String (Int, List Bits8)
decodeInt32 (b1 :: b2 :: b3 :: b4 :: rest) =
  let raw : Int
      raw = shiftL (cast b1) 24
          + shiftL (cast b2) 16
          + shiftL (cast b3) 8
          + cast b4
      signed : Int
      signed = if raw >= 0x80000000 then raw - 0x100000000 else raw
  in Right (signed, rest)
decodeInt32 _ = Left "decodeInt32: insufficient bytes"

-- Built via Integer (arbitrary precision, never overflows) rather than
-- Int, unlike decodeInt16/32: Int is only guaranteed to be 64 bits wide,
-- exactly as wide as the value being decoded, so there's no headroom for
-- the same "build unsigned, then reinterpret as signed" trick those use -
-- e.g. the unsigned magnitude of INT64_MIN (2^63) doesn't fit in a
-- positive Int64 at all. Integer sidesteps that entirely.
public export
decodeInt64 : Bytes -> Either String (Int, Bytes)
decodeInt64 (b1 :: b2 :: b3 :: b4 :: b5 :: b6 :: b7 :: b8 :: rest) =
  let raw : Integer
      raw = (cast b1 * 72057594037927936)   -- 256^7
          + (cast b2 * 281474976710656)     -- 256^6
          + (cast b3 * 1099511627776)       -- 256^5
          + (cast b4 * 4294967296)          -- 256^4
          + (cast b5 * 16777216)            -- 256^3
          + (cast b6 * 65536)               -- 256^2
          + (cast b7 * 256)
          + cast b8
      signed : Integer
      signed = if raw >= 9223372036854775808          -- 2^63
                  then raw - 18446744073709551616      -- 2^64
                  else raw
  in Right (fromInteger signed, rest)
decodeInt64 _ = Left "decodeInt64: insufficient bytes"

-- Encode/decode null-terminated UTF8 string
public export
encodeCString : String -> List Bits8
encodeCString s = stringToBytes s ++ [0]

public export
decodeCString : List Bits8 -> Either String (String, List Bits8)
decodeCString bs =
  case span (/= 0) bs of
    (chars, 0 :: rest) => Right (bytesToString chars, rest)
    _ => Left "decodeCString: unterminated string"

eitherToMaybe : Either e a -> Maybe a
eitherToMaybe (Left _) = Nothing
eitherToMaybe (Right v) = Just v

public export
decodeFieldDesc : List Bits8 -> Maybe (FieldDescription, List Bits8)
decodeFieldDesc bs = do
  (name, afterName) <- eitherToMaybe (decodeCString bs)
  (tableOID, a1) <- eitherToMaybe (decodeInt32 afterName)
  (colAttr, a2) <- eitherToMaybe (decodeInt16 a1)
  (typeOID, a3) <- eitherToMaybe (decodeInt32 a2)
  (typeSize, a4) <- eitherToMaybe (decodeInt16 a3)
  (typeMod, a5) <- eitherToMaybe (decodeInt32 a4)
  (formatCode, rest) <- eitherToMaybe (decodeInt16 a5)
  pure (MkFieldDescription name tableOID colAttr typeOID typeSize typeMod formatCode, rest)

public export
decodeRowDescFields : Int -> List Bits8 -> Maybe (List FieldDescription)
decodeRowDescFields 0 bs = Just []
decodeRowDescFields n bs = do
  (field, rest) <- decodeFieldDesc bs
  more <- decodeRowDescFields (n - 1) rest
  pure (field :: more)

-- ErrorResponse/NoticeResponse payload: a sequence of (1-byte field code,
-- null-terminated string) pairs, terminated by a final 0x00 byte.
public export
decodeNoticeFields : Bytes -> Either String (List NoticeField)
decodeNoticeFields [] = Right []
decodeNoticeFields (0 :: _) = Right []
decodeNoticeFields (tagByte :: rest) = do
  (val, afterVal) <- decodeCString rest
  more <- decodeNoticeFields afterVal
  Right (MkField (chr (cast tagByte)) val :: more)

fieldValue : Char -> List NoticeField -> Maybe String
fieldValue c [] = Nothing
fieldValue c (f :: fs) = if tag f == c then Just (value f) else fieldValue c fs

public export
mkError : List NoticeField -> Error
mkError fields = MkError (fieldValue 'S' fields) (fieldValue 'C' fields)
                          (fromMaybe "" (fieldValue 'M' fields)) fields

public export
decodeInt32List : Nat -> Bytes -> Either String (List Int)
decodeInt32List Z bs = Right []
decodeInt32List (S k) bs = do
  (oid, rest) <- decodeInt32 bs
  more <- decodeInt32List k rest
  Right (oid :: more)

public export
decodeInt16List : Nat -> Bytes -> Either String (List Int)
decodeInt16List Z bs = Right []
decodeInt16List (S k) bs = do
  (v, rest) <- decodeInt16 bs
  more <- decodeInt16List k rest
  Right (v :: more)


-- Every send/receive on an established connection goes through these two,
-- rather than the raw socket directly: once TLS has been negotiated (see
-- connectPG), conn.tls holds a Just, and every byte gets AEAD-sealed/
-- opened by Network.TLS instead of touching the socket directly.
public export
pgSend : PGConnection Connected -> Bytes -> IO (Either String ())
pgSend conn bytes = do
  mSession <- readIORef (tls conn)
  case mSession of
       Nothing      => send (MkConnected (socket conn)) bytes
       Just session => tlsSend session bytes

public export
pgReceiveExact : PGConnection Connected -> Int -> IO (Either String Bytes)
pgReceiveExact conn n = do
  mSession <- readIORef (tls conn)
  case mSession of
       Nothing      => receiveExact (MkConnected (socket conn)) n
       Just session => tlsReceiveExact session n

public export
readFrameBit : (PGConnection Connected) -> IO (Either String FrameBytes)
readFrameBit conn = do
  msgTypeResp <- pgReceiveExact conn 1
  case msgTypeResp of
       (Left x) => pure (Left x)
       (Right tagByte) => do
          lenRes <- pgReceiveExact conn 4
          case lenRes of
              (Left x) => pure (Left x)
              (Right lenList) => do
                    let vect = toVect 4 lenList
                    case vect of
                         Nothing => pure (Left "Error parsing length")
                         (Just lenVect) => case validateFrameLength (toInt lenVect) of
                              Left err => pure (Left err)
                              Right payloadLen => do
                                payloadRes <- pgReceiveExact conn payloadLen
                                case payloadRes of
                                     (Left y) => pure (Left y)
                                     (Right y) => pure (Right(MkFrameBytes tagByte lenList y))


-- Postgres's SSLRequest: an untagged 8-byte message (length + the special
-- SSLRequest code, same "no tag byte" shape as CancelRequest), answered
-- with a single 'S' (proceed with a TLS handshake on this same socket) or
-- 'N' (the server doesn't support SSL).
sslRequestBytes : Bytes
sslRequestBytes = encodeInt32 8 ++ encodeInt32 80877103

public export
connectPG : String -> Int -> (wantTLS : Bool) -> Maybe String -> IO (Either String (PGConnection Connected))
connectPG host port wantTLS caFile = do
  False <- pure ((not wantTLS && isJust caFile) || elem '\0' (unpack host))
    | True => pure (Left "TLS configuration requires useTLS and a valid host")
  sockRes <- getSock
  case sockRes of
    Left _ => pure (Left "could not create socket")
    Right socket => do
      -- Hostname is resolved via getaddrinfo at the C layer, which handles
      -- both real hostnames and dotted-quad/numeric addresses.
      connRes <- getConnection socket (Hostname host) port
      case connRes of
        Nothing => do
          Network.Socket.close socket
          pure (Left "could not connect")
        Just _  =>
          if not wantTLS
             then do
               tlsRef <- newIORef Nothing
               pure (Right (MkPGConnection socket [] tlsRef))
             else negotiateTLS socket
  where
    negotiateTLS : Socket -> IO (Either String (PGConnection Connected))
    negotiateTLS socket = do
      sendRes <- send (MkConnected socket) sslRequestBytes
      case sendRes of
           Left err => do
             Network.Socket.close socket
             pure (Left ("could not send SSLRequest: " ++ err))
           Right () => do
             respRes <- receiveExact (MkConnected socket) 1
             case respRes of
                  Left err => do
                    Network.Socket.close socket
                    pure (Left ("could not read SSLRequest response: " ++ err))
                  Right [0x53] => do -- 'S': server will speak TLS from here
                    tlsRes <- tlsClientHandshake socket host caFile
                    case tlsRes of
                         Left err => do
                           Network.Socket.close socket
                           pure (Left ("TLS handshake failed: " ++ err))
                         Right session => do
                           tlsRef <- newIORef (Just session)
                           pure (Right (MkPGConnection socket [] tlsRef))
                  Right [0x4e] => do -- 'N': no SSL support, and useTLS means this is fatal
                    Network.Socket.close socket
                    pure (Left "server does not support SSL")
                  Right _ => do
                    Network.Socket.close socket
                    pure (Left "unexpected response to SSLRequest")


||| Release TLS before closing its owned socket, on every connection exit path.
public export
closePGConnection : PGConnection Connected -> IO ()
closePGConnection conn = do
  session <- readIORef (tls conn)
  writeIORef (tls conn) Nothing
  traverse_ tlsClose session
  Network.Socket.close (socket conn)

public export
sendStartup : PGConnection Connected -> List Bits8 -> IO (Maybe (PGConnection StartupSent))
sendStartup conn msg = do
  res <- pgSend conn msg
  case res of
       (Left x) => pure Nothing
       (Right x) => pure (Just (MkPGConnection (socket conn) [] (tls conn)))

-- Keeps raw bytes rather than decoding to String here: a column can be in
-- binary format, whose bytes generally aren't valid UTF-8 text. See
-- DataRow.columns.
parseColumns : Nat -> Bytes -> Either String (List (Maybe Bytes))
parseColumns Z rest = Right []
parseColumns (S k) bs = do
  (len, afterLen) <- decodeInt32 bs
  case len == -1 of
      True => do
        rest <- parseColumns k afterLen
        Right (Nothing :: rest)
      False => do
        let val = take (cast len) afterLen
        rest <- parseColumns k (drop (cast len) afterLen)
        Right (Just val :: rest)


public export
encode : PGMsg -> Bytes
encode (StartupMsg proto params) =
  let keyvals = concatMap (\(k, v) => encodeCString k ++ encodeCString v) params
      proto  = [0x00, 0x03, 0x00, 0x00]  -- protocol 3.0
      payload = proto ++ keyvals ++[0] --encodeInt32 proto ++ keyvals ++ [0]  -- terminator
      len = 4 + length payload
  in  encodeInt32 (cast len) ++ payload

encode (QueryMsg query) =
  let payload = encodeCString (body query)
      len = 4 + length payload
      in [toByte QueryTag] ++ encodeInt32 (cast len) ++ payload

encode (PasswordMessage pw) =
  let payload = encodeCString pw
      len = 4 + length payload
  in [0x70] ++ encodeInt32 (cast len) ++ payload  -- 'p'

encode (SASLInitialResponse mechanism responseData) =
  let payload = encodeCString mechanism ++ encodeInt32 (cast (length responseData)) ++ responseData
      len = 4 + length payload
  in [0x70] ++ encodeInt32 (cast len) ++ payload  -- 'p'

encode (SASLResponse responseData) =
  let len = 4 + length responseData
  in [0x70] ++ encodeInt32 (cast len) ++ responseData  -- 'p'

encode Terminate = [0x58] ++ encodeInt32 4  -- 'X', no payload

encode (Parse stmtName query paramTypes) =
  let payload = encodeCString stmtName ++ encodeCString query
                  ++ encodeInt16 (cast (length paramTypes))
                  ++ concatMap encodeInt32 paramTypes
      len = 4 + length payload
  in [0x50] ++ encodeInt32 (cast len) ++ payload  -- 'P'

encode (Bind portal stmtName params binaryResults) =
  let encodeParam : Maybe Bytes -> Bytes
      encodeParam Nothing = encodeInt32 (-1)
      encodeParam (Just bytes) = encodeInt32 (cast (length bytes)) ++ bytes
      -- A single format code (rather than one per column) applies to all
      -- of them - 0 = text, 1 = binary.
      resultFormatSection : Bytes
      resultFormatSection = if binaryResults then encodeInt16 1 ++ encodeInt16 1 else encodeInt16 0
      payload = encodeCString portal ++ encodeCString stmtName
                  ++ encodeInt16 0  -- all parameters are text format
                  ++ encodeInt16 (cast (length params))
                  ++ concatMap encodeParam params
                  ++ resultFormatSection
      len = 4 + length payload
  in [0x42] ++ encodeInt32 (cast len) ++ payload  -- 'B'

encode (Describe kind name) =
  let payload = [cast (ord kind)] ++ encodeCString name
      len = 4 + length payload
  in [0x44] ++ encodeInt32 (cast len) ++ payload  -- 'D'

encode (Execute portal maxRows) =
  let payload = encodeCString portal ++ encodeInt32 maxRows
      len = 4 + length payload
  in [0x45] ++ encodeInt32 (cast len) ++ payload  -- 'E'

encode Sync = [0x53] ++ encodeInt32 4  -- 'S', no payload

-- No tag byte: just length(=16), the fixed cancel-request magic code, pid, secret.
encode (CancelRequest pgPid pgSecret) =
  encodeInt32 16 ++ encodeInt32 80877102 ++ encodeInt32 pgPid ++ encodeInt32 pgSecret

encode (CopyData bytes) =
  let len = 4 + length bytes
  in [0x64] ++ encodeInt32 (cast len) ++ bytes  -- 'd'

encode CopyDone = [0x63] ++ encodeInt32 4  -- 'c', no payload

encode (CopyFail msg) =
  let payload = encodeCString msg
      len = 4 + length payload
  in [0x66] ++ encodeInt32 (cast len) ++ payload  -- 'f'

encode _ =  ?unimplementedEncode

public export
decode : FrameBytes -> Either String PGMsg
decode (MkFrameBytes [] len payload) = Left "Tag is Empty"
decode (MkFrameBytes (x :: xs) [] payload) = Left "Length is Empty"
decode (MkFrameBytes (tag :: xs) (y :: ys) payload) = do
  case tagFromString (bytesToString [tag]) of
       AuthenticationTag => case decodeInt32 payload of
            Right (authCode, salt) => Right (AuthenticationMsg (parseAuthResponse authCode salt))
            Left e => Left e

       BackendKeyDataTag => case decodeInt32 payload of
            Right (pid, afterPid) =>
              case decodeInt32 afterPid of
                Right (secret, _) => Right (BackendKeyDataMsg (MkBackendKeyData pid secret))
                Left e => Left e
            Left e => Left e

       BindCompleteTag => Right BindCompleteMsg
       CloseCompleteTag => Right CloseCompleteMsg

       CommandCompleteTag => case decodeCString payload of
            Right (s, _) => Right (CommandCompleteMsg s)
            Left e => Left e

       DataRowTag => do
         (nCols, rest) <- decodeInt16 payload
         let datarows = parseColumns (cast nCols) rest
         case datarows of
              (Left err) => Left err
              (Right x) => Right (DataRowMsg (MkDataRow nCols x))


       EmptyQueryResponseTag => Right EmptyQueryResponseMsg

       ErrorResponseTag => case decodeNoticeFields payload of
            Right fields => Right (ErrorMsg (mkError fields))
            Left e => Left e

       NoticeResponseTag => case decodeNoticeFields payload of
            Right fields => Right (NoticeMsg (MkNotice fields))
            Left e => Left e

       NotificationResponseTag => case decodeInt32 payload of
            Right (pgPid, afterPid) => case decodeCString afterPid of
                 Right (channel, afterChannel) => case decodeCString afterChannel of
                      Right (msg, _) => Right (NotificationMsg (MkNotification pgPid channel msg))
                      Left e => Left e
                 Left e => Left e
            Left e => Left e

       ParameterDescriptionTag => case decodeInt16 payload of
            Right (n, rest) => case decodeInt32List (cast n) rest of
                 Right oids => Right (ParameterDescriptionMsg oids)
                 Left e => Left e
            Left e => Left e

       ParameterStatusTag => case decodeCString payload of
            Right (key, afterKey) =>
              case decodeCString afterKey of
                Right (val, _) => Right (ParameterStatusMsg (MkParameterStatus key val))
                Left e => Left e
            Left e => Left e

       ParseCompleteTag => Right ParseCompleteMsg
       PortalSuspendedTag => Right PortalSuspendedMsg
       ReadyForQueryTag => do
          case payload of
            [b] => Right (ReadyForQueryMsg (fromByte b))
            _   => Left "Invalid ReadyForQuery payload"

       RowDescriptionTag => case decodeInt16 payload of
            Right (nfields, rest) =>
              case decodeRowDescFields nfields rest of
                Just fields => Right (RowDescriptionMsg (MkRowDescription fields))
                Nothing => Left "Failed to parse RowDescription fields"
            Left e => Left e

       QueryTag => Right (UnknownMsg QueryTag payload)

       CopyDataTag => Right (CopyData payload)
       CopyDoneTag => Right CopyDone

       CopyOutResponseTag => case payload of
            (fmtByte :: rest) => case decodeInt16 rest of
                 Right (n, afterCount) => case decodeInt16List (cast n) afterCount of
                      Right codes => Right (CopyOutResponseMsg (cast fmtByte) codes)
                      Left e => Left e
                 Left e => Left e
            [] => Left "CopyOutResponse: empty payload"

       CopyInResponseTag => case payload of
            (fmtByte :: rest) => case decodeInt16 rest of
                 Right (n, afterCount) => case decodeInt16List (cast n) afterCount of
                      Right codes => Right (CopyInResponseMsg (cast fmtByte) codes)
                      Left e => Left e
                 Left e => Left e
            [] => Left "CopyInResponse: empty payload"

       (UnknownTag str) => Right (UnknownMsg (UnknownTag str) payload)

public export
readFrame : PGConnection Connected -> IO (Either String PGMsg)
readFrame conn = do
  frameRes <- readFrameBit conn
  case frameRes of
       (Left err) => pure (Left err)
       (Right frameBytes) => case (decode frameBytes) of
             (Left err) => pure (Left err)
             (Right msg) => pure (Right msg)


startupstep : StartupResult -> PGMsg -> StartupResult
startupstep acc (AuthenticationMsg a) = { authState := Just a } acc 
startupstep acc (ParameterStatusMsg p)= { params := acc.params ++ [p] } acc
startupstep acc (BackendKeyDataMsg b) = { backendKey := Just b } acc
startupstep acc (ReadyForQueryMsg r)  = { ready := Just (MkReadyForQuery r) } acc
startupstep acc (ErrorMsg e)          = { errors := acc.errors ++ [e] } acc
startupstep acc (NoticeMsg n)         = { notices := acc.notices ++ [n] } acc
startupstep acc _                     = acc


public export
-- Tracked from AuthenticationSASL through AuthenticationSASLFinal - see
-- handleStartupResponse's SCRAM branches below. ScramVerified is reached
-- only once verifyServerFinal has actually succeeded; AuthenticationOk is
-- refused in every other state except ScramNotStarted (a non-SCRAM auth
-- method), so a server can't skip straight to AuthenticationOk without
-- ever proving it knows the password verifier.
data ScramProgress
  = ScramNotStarted
  | ScramAwaitingServerFirst String String  -- client nonce, client-first-message-bare
  | ScramAwaitingServerFinal Bytes          -- expected ServerSignature
  | ScramVerified

-- SASL mechanism-list payload: null-terminated strings, no extra wrapping.
offersScramSha256 : Bytes -> Bool
offersScramSha256 bs = case decodeCString bs of
     Right ("SCRAM-SHA-256", _) => True
     Right (_, rest)            => offersScramSha256 rest
     Left _                     => False

public export
handleStartupResponse : (user : String) -> (password : String) -> PGConnection Connected -> IO (Either PGError StartupResult)
handleStartupResponse user password conn = go ScramNotStarted init
  where
    init : StartupResult
    init = MkStartupResult Nothing [] Nothing Nothing [] []

    -- Nothing on the wire went wrong, but this session can't proceed
    -- (unsupported auth method) - a protocol-level failure, not a query error.
    unsupported : String -> IO (Either PGError StartupResult)
    unsupported msg = pure (Left (ProtocolError msg))

    sendPassword : String -> IO (Either PGError ())
    sendPassword pw = do
      res <- pgSend conn (encode (PasswordMessage pw))
      case res of
           Left err => pure (Left (ConnectionError err))
           Right () => pure (Right ())

    sendFrame : Bytes -> IO (Either PGError ())
    sendFrame bytes = do
      res <- pgSend conn bytes
      case res of
           Left err => pure (Left (ConnectionError err))
           Right () => pure (Right ())

    go : ScramProgress -> StartupResult -> IO (Either PGError StartupResult)
    go scram acc = do
      bs <- readFrame conn
      case bs of
        Left err => pure (Left (ConnectionError err))
        Right msg =>
              case msg of
                -- Returned immediately rather than accumulated and kept
                -- looping: Postgres closes the connection right after an
                -- auth-failure ErrorMsg, so looping on would just replace
                -- this, the real cause, with a generic EOF/connection
                -- error once the next readFrame fails.
                ErrorMsg e => pure (Left (SqlError e))
                -- connectDB treats handleStartupResponse returning Right
                -- (i.e. this ReadyForQuery branch) as the actual signal
                -- the connection succeeded - AuthenticationOk isn't
                -- checked by the caller at all. So this needs the exact
                -- same SCRAM-completion guard as AuthOk below: a server
                -- could otherwise skip both AuthenticationSASLFinal *and*
                -- AuthenticationOk, jumping straight from the client's
                -- proof to ReadyForQuery, and slip through untouched.
                ReadyForQueryMsg r =>
                  case scram of
                       ScramAwaitingServerFirst _ _ =>
                         unsupported "connection reached ReadyForQuery without completing SCRAM authentication (server never sent its final signature)"
                       ScramAwaitingServerFinal _ =>
                         unsupported "connection reached ReadyForQuery without completing SCRAM authentication (server never sent its final signature)"
                       _ => pure (Right ({ ready := Just (MkReadyForQuery r) } acc))
                AuthenticationMsg AuthOk =>
                  -- Refuses AuthenticationOk unless SCRAM either never
                  -- started (a different auth method) or fully completed
                  -- (ScramVerified, set only after verifyServerFinal
                  -- succeeded below) - otherwise a server could request
                  -- SCRAM, receive the client's proof, and skip straight
                  -- to AuthenticationOk without ever proving it knows the
                  -- password verifier itself.
                  case scram of
                       ScramAwaitingServerFirst _ _ =>
                         unsupported "SCRAM authentication did not complete before AuthenticationOk (server never sent its final signature)"
                       ScramAwaitingServerFinal _ =>
                         unsupported "SCRAM authentication did not complete before AuthenticationOk (server never sent its final signature)"
                       _ => go scram ({ authState := Just AuthOk } acc)
                AuthenticationMsg AuthCleartext => do
                  sent <- sendPassword password
                  case sent of
                       Left err => pure (Left err)
                       Right () => go scram ({ authState := Just AuthCleartext } acc)
                AuthenticationMsg (AuthMD5 salt) => do
                  let hashed = pgMD5Password password user salt
                  sent <- sendPassword hashed
                  case sent of
                       Left err => pure (Left err)
                       Right () => go scram ({ authState := Just (AuthMD5 salt) } acc)

                AuthenticationMsg (AuthSASL mechs) =>
                  if not (offersScramSha256 mechs)
                     then unsupported "server does not offer SCRAM-SHA-256 (only mechanism supported here)"
                     else do
                       clientNonce <- genClientNonce
                       let bare = clientFirstMessageBare clientNonce
                           full = clientFirstMessage clientNonce
                       sent <- sendFrame (encode (SASLInitialResponse "SCRAM-SHA-256" (stringToBytes full)))
                       case sent of
                            Left err => pure (Left err)
                            Right () => go (ScramAwaitingServerFirst clientNonce bare) (startupstep acc msg)

                AuthenticationMsg (AuthSASLContinue contBytes) =>
                  case scram of
                       ScramAwaitingServerFirst clientNonce bare =>
                         let serverFirstRaw = bytesToString contBytes
                         in case parseServerFirstMessage serverFirstRaw of
                                 Nothing => unsupported "malformed SCRAM server-first-message"
                                 Just sf =>
                                   case computeClientFinal password clientNonce bare serverFirstRaw sf of
                                        Nothing => unsupported "SCRAM server nonce does not extend the client nonce"
                                        Just cf => do
                                          sent <- sendFrame (encode (SASLResponse (stringToBytes (message cf))))
                                          case sent of
                                               Left err => pure (Left err)
                                               Right () => go (ScramAwaitingServerFinal (expectedServerSignature cf)) (startupstep acc msg)
                       _ => unsupported "unexpected SCRAM server-first-message"

                AuthenticationMsg (AuthSASLFinal finalBytes) =>
                  case scram of
                       ScramAwaitingServerFinal expectedSig =>
                         if verifyServerFinal (bytesToString finalBytes) expectedSig
                            then go ScramVerified (startupstep acc msg)
                            else unsupported "SCRAM server signature verification failed (possible MITM or protocol error)"
                       _ => unsupported "unexpected SCRAM server-final-message"

                AuthenticationMsg (AuthUnknown n) =>
                  unsupported ("Unsupported authentication method: " ++ show n)
                _                  => go scram (startupstep acc msg)


-- Prepends (O(1)) rather than `acc.rows ++ [row]` (O(n) per row, O(n^2)
-- total for n rows in one result set) - rows/errors/notices end up
-- reversed, so finalizeQueryResult below un-reverses them once a
-- QueryResult is complete, rather than paying the append cost on every
-- message.
querystep : QueryResult -> PGMsg -> QueryResult
querystep acc (RowDescriptionMsg rd) = { description := Just rd } acc
querystep acc (DataRowMsg row)       = { rows := row :: acc.rows } acc
querystep acc (ErrorMsg e)           = { errors := e :: acc.errors } acc
querystep acc (NoticeMsg n)          = { notices := n :: acc.notices } acc
querystep acc _                      = acc

finalizeQueryResult : QueryResult -> QueryResult
finalizeQueryResult qr =
  { rows := reverse qr.rows, errors := reverse qr.errors, notices := reverse qr.notices } qr

emptyQueryResult : QueryResult
emptyQueryResult = MkQueryResult Nothing [] Nothing Nothing [] []

setStatusOnLast : ReadyForQuery -> List QueryResult -> List QueryResult
setStatusOnLast r []        = [{ status := Just r } emptyQueryResult]
setStatusOnLast r [x]       = [{ status := Just r } x]
setStatusOnLast r (x :: xs) = x :: setStatusOnLast r xs

-- Postgres's simple query protocol allows multiple ';'-separated statements
-- in one Query message, each yielding its own RowDescription/DataRow*/
-- CommandComplete (or EmptyQueryResponse for a blank statement) before a
-- single final ReadyForQuery. `pending` accumulates the statement currently
-- in progress; it flushes into `completed` at each CommandComplete/
-- EmptyQueryResponse boundary, so each statement gets its own QueryResult
-- instead of one merged/corrupted result.
public export
handleQueryResponses : DB -> IO (Either PGError (List QueryResult))
handleQueryResponses db = go Nothing []
  where
    go : Maybe QueryResult -> List QueryResult -> IO (Either PGError (List QueryResult))
    go pending completed = do
      bs <- readFrame (conn db)
      case bs of
        Left err => pure (Left (ConnectionError err))
        Right msg =>
          let acc = fromMaybe emptyQueryResult pending in
          case msg of
               ReadyForQueryMsg r =>
                 case pending of
                      Nothing => pure (Right (setStatusOnLast (MkReadyForQuery r) completed))
                      Just _  => pure (Right (completed ++ [finalizeQueryResult ({ status := Just (MkReadyForQuery r) } acc)]))
               CommandCompleteMsg c => go Nothing (completed ++ [finalizeQueryResult ({ commandTag := Just c } acc)])
               EmptyQueryResponseMsg => go Nothing (completed ++ [finalizeQueryResult acc])
               -- NotificationResponse is an asynchronous message Postgres
               -- can deliver interleaved with any query's own responses,
               -- not just while waitForNotification is the one reading -
               -- most importantly, it can arrive between a statement's
               -- CommandComplete and the batch's final ReadyForQuery, when
               -- `pending` is already Nothing. Folding it through
               -- querystep like an ordinary message would wrongly conjure
               -- up a new `pending` QueryResult for it (extending
               -- `completed` with a phantom entry once ReadyForQuery
               -- arrives), so it's queued instead, leaving pending/
               -- completed untouched either way.
               NotificationMsg n => do
                 modifyIORef (notifQueue db) (++ [n])
                 go pending completed
               _ => go (Just (querystep acc msg)) completed
