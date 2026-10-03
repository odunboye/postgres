module Data.PGTypes

import Derive.Prelude
import Data.Bits
import Data.IORef
import Network.Socket
import Network.Core
import Network.TLS

%language ElabReflection
%default total

public export
data PGState
  = Disconnected
  | Connected
  | StartupSent
  | Closed

public export
record PGConnection (state : PGState) where
  constructor MkPGConnection
  socket : Socket
  params : List (String, String)  -- e.g. user, database
  -- Set once (by the SSLRequest negotiation in Helper.connectPG) if this
  -- connection upgraded to TLS; Nothing means every send/receive goes
  -- straight to the raw socket, unchanged from before TLS support existed.
  tls    : IORef (Maybe TLSSession)
--%runElab derive "PGConnection" [Show, Eq]

public export
mkConnectedPG : (PGConnection StartupSent) -> (PGConnection Connected)
mkConnectedPG (MkPGConnection socket params tls) = MkPGConnection socket params tls

public export
Bytes : Type
Bytes = List Bits8
 
public export
data Tag
  = AuthenticationTag         -- 'R'
  | BackendKeyDataTag         -- 'K'
  | BindCompleteTag           -- '2'
  | CloseCompleteTag          -- '3'
  | CommandCompleteTag        -- 'C'
  | DataRowTag                -- 'D'
  | EmptyQueryResponseTag     -- 'I'
  | ErrorResponseTag          -- 'E'
  | NoticeResponseTag         -- 'N'
  | NotificationResponseTag   -- 'A'
  | ParameterDescriptionTag   -- 't'
  | ParameterStatusTag        -- 'S'
  | ParseCompleteTag          -- '1'
  | PortalSuspendedTag        -- 's'
  | ReadyForQueryTag          -- 'Z'
  | RowDescriptionTag         -- 'T'
  | QueryTag                  -- 'Q'
  | CopyDataTag               -- 'd'
  | CopyDoneTag               -- 'c'
  | CopyOutResponseTag        -- 'H'
  | CopyInResponseTag         -- 'G'
  | UnknownTag String

%runElab derive "Tag" [Show, Eq]

public export
tagFromString : String -> Tag
tagFromString s =
  case s of
    "R" => AuthenticationTag
    "K" => BackendKeyDataTag
    "2" => BindCompleteTag
    "3" => CloseCompleteTag
    "C" => CommandCompleteTag
    "D" => DataRowTag
    "I" => EmptyQueryResponseTag
    "E" => ErrorResponseTag
    "N" => NoticeResponseTag
    "A" => NotificationResponseTag
    "t" => ParameterDescriptionTag
    "S" => ParameterStatusTag
    "1" => ParseCompleteTag
    "s" => PortalSuspendedTag
    "Z" => ReadyForQueryTag
    "T" => RowDescriptionTag
    "Q" => QueryTag
    "d" => CopyDataTag
    "c" => CopyDoneTag
    "H" => CopyOutResponseTag
    "G" => CopyInResponseTag
    _   => UnknownTag s

public export
data PGAuthResponseTag
  = AuthOk
  | AuthCleartext
  | AuthMD5 Bytes
  | AuthSASL Bytes           -- code 10: raw mechanism-list bytes (parsed in Helper.idr, which has decodeCString)
  | AuthSASLContinue Bytes   -- code 11: raw server-first-message bytes
  | AuthSASLFinal Bytes      -- code 12: raw server-final-message bytes
  | AuthUnknown Int
%runElab derive "PGAuthResponseTag" [Show, Eq]

public export
parseAuthResponse : Int -> Bytes -> PGAuthResponseTag
parseAuthResponse i rest =
  case i of
    0  => AuthOk
    3  => AuthCleartext
    5  => AuthMD5 rest
    10 => AuthSASL rest
    11 => AuthSASLContinue rest
    12 => AuthSASLFinal rest
    n  => AuthUnknown n

public export
toByte : Tag -> Bits8
toByte ReadyForQueryTag          = 0x5A  -- 'Z'
toByte AuthenticationTag         = 0x52  -- 'R'
toByte ErrorResponseTag          = 0x45  -- 'E'
toByte ParameterStatusTag        = 0x53  -- 'S'
toByte BackendKeyDataTag         = 0x4B  -- 'K'
toByte DataRowTag                = 0x44  -- 'D'
toByte RowDescriptionTag         = 0x54  -- 'T'
toByte CommandCompleteTag        = 0x43  -- 'C'
toByte BindCompleteTag           = 0x32  -- '2'
toByte CloseCompleteTag          = 0x33  -- '3'
toByte EmptyQueryResponseTag     = 0x49  -- 'I'
toByte NoticeResponseTag         = 0x4E  -- 'N'
toByte NotificationResponseTag   = 0x41  -- 'A'
toByte ParameterDescriptionTag   = 0x74  -- 't'
toByte ParseCompleteTag          = 0x31  -- '1'
toByte PortalSuspendedTag        = 0x73  -- 's'
toByte QueryTag                  = 0x51  -- 'Q'
toByte CopyDataTag               = 0x64  -- 'd'
toByte CopyDoneTag               = 0x63  -- 'c'
toByte CopyOutResponseTag        = 0x48  -- 'H'
toByte CopyInResponseTag         = 0x47  -- 'G'
toByte (UnknownTag b)         = cast b

public export
data TxStatus
  = Idle
  | InTransaction
  | FailedTransaction
  | UnknownStatus Bits8
%runElab derive "TxStatus" [Show, Eq]

public export
fromByte : Bits8 -> TxStatus
fromByte 0x49 = Idle
fromByte 0x54 = InTransaction
fromByte 0x45 = FailedTransaction
fromByte b    = UnknownStatus b

public export
record ReadyForQuery where
  constructor MkReadyForQuery
  status : TxStatus
%runElab derive "ReadyForQuery" [Show, Eq]

public export
record FieldDescription where
  constructor MkFieldDescription
  name : String
  tableOID : Int
  columnAttr : Int
  typeOID : Int
  typeSize : Int
  typeMod : Int
  formatCode : Int
%runElab derive "FieldDescription" [Show, Eq]

public export
record RowDescription where
  constructor MkRowDescription
  fields : List FieldDescription
%runElab derive "RowDescription" [Show, Eq]

public export
record DataRow where
  constructor MkDataRow
  columnCount : Int
  -- Raw bytes, not decoded to String here: a column can be in binary
  -- format (see Bind's binaryResults flag and FieldDescription.formatCode),
  -- whose bytes generally aren't valid UTF-8 text. Text-vs-binary decoding
  -- happens in Data.PGValue, which has the per-column format available.
  columns     : List (Maybe Bytes)
%runElab derive "DataRow" [Show, Eq]


public export
record ParameterStatus where
  constructor MkParameterStatus
  key : String 
  val : String
%runElab derive "ParameterStatus" [Show, Eq]


public export
record BackendKeyData where
  constructor MkBackendKeyData
  pid : Int
  secret : Int
%runElab derive "BackendKeyData" [Show, Eq]

||| A LISTEN/NOTIFY payload from the server. Decoding is complete, but
||| nothing sends LISTEN or waits for these yet - that needs a way to read
||| without blocking, which this client doesn't have.
public export
record Notification where
  constructor MkNotification
  pid     : Int
  channel : String
  payload : String
%runElab derive "Notification" [Show, Eq]


public export
record NoticeField where
  constructor MkField
  tag : Char
  value : String
%runElab derive "NoticeField" [Show, Eq]

public export
record Notice where
  constructor MkNotice
  fields : List NoticeField
%runElab derive "Notice" [Show, Eq]

public export
record Error where
  constructor MkError
  severity : Maybe String
  code     : Maybe String
  message  : String
  raw      : List NoticeField
%runElab derive "Error" [Show, Eq]

-- Field codes per the Postgres protocol's ErrorResponse/NoticeResponse
-- message format (the ones not already broken out above as severity/code).
lookupField : Char -> Error -> Maybe String
lookupField c e = go (raw e)
  where
    go : List NoticeField -> Maybe String
    go [] = Nothing
    go (f :: fs) = if tag f == c then Just (value f) else go fs

public export
detail, hint, position, schemaName, tableName, columnName, dataTypeName, constraintName
  : Error -> Maybe String
detail         = lookupField 'D'
hint           = lookupField 'H'
position       = lookupField 'P'
schemaName     = lookupField 's'
tableName      = lookupField 't'
columnName     = lookupField 'c'
dataTypeName   = lookupField 'd'
constraintName = lookupField 'n'

||| Distinguishes transport-level failures, protocol-level surprises, and
||| genuine SQL errors reported by the server, so callers can decide whether
||| e.g. a retry makes sense without string-matching an error message.
public export
data PGError
  = ConnectionError String
  | ProtocolError String
  | SqlError Error
%runElab derive "PGError" [Show]

public export
displayError : PGError -> String
displayError (ConnectionError s) = "connection error: " ++ s
displayError (ProtocolError s)   = "protocol error: " ++ s
displayError (SqlError e)        = "SQL error: " ++ message e

public export
record Query  where
  constructor MkQuery
  body : String
%runElab derive "Query" [Show, Eq]

public export
data PGMsg
  = StartupMsg Int (List (String, String))
  | QueryMsg Query
  | PasswordMessage String
  -- SCRAM-SHA-256 (RFC 5802/7677): both wire-encode to tag 'p', same as
  -- PasswordMessage - which one the server expects depends on which
  -- authentication method it requested, not a different tag byte.
  | SASLInitialResponse String Bytes  -- mechanism name, initial response data
  | SASLResponse Bytes                -- response data (no mechanism name this time)
  | Terminate
  -- Extended query protocol (parameterized queries): unnamed statement/portal
  -- names ("") are used throughout since this client doesn't cache/reuse
  -- prepared statements across calls.
  | Parse String String (List Int)             -- stmt name, query, param type OIDs (0 = infer)
  | Bind String String (List (Maybe Bytes)) Bool -- portal, stmt, text-encoded params (Nothing = NULL), request binary results
  | Describe Char String                        -- 'S' (statement) or 'P' (portal), name
  | Execute String Int                          -- portal, max rows (0 = unlimited)
  | Sync
  -- Not a normal tag-prefixed message: sent alone on a fresh connection to
  -- ask the server to cancel whatever the given backend is running.
  | CancelRequest Int Int                       -- backend PID, backend secret key
  -- COPY protocol (bulk import/export). CopyData/CopyDone are bidirectional
  -- (the client sends them for COPY FROM STDIN; the server sends them for
  -- COPY TO STDOUT); CopyFail is client-only, the response messages are
  -- server-only.
  | CopyData Bytes
  | CopyDone
  | CopyFail String
  | CopyOutResponseMsg Int (List Int)           -- overall format (0=text,1=binary), per-column format codes
  | CopyInResponseMsg Int (List Int)
  | ReadyForQueryMsg  TxStatus
  | AuthenticationMsg PGAuthResponseTag
  | ErrorMsg Error
  | ParameterStatusMsg ParameterStatus
  | BackendKeyDataMsg BackendKeyData
  | DataRowMsg DataRow
  | RowDescriptionMsg  RowDescription
  | CommandCompleteMsg String
  | NoticeMsg Notice
  | ParseCompleteMsg
  | BindCompleteMsg
  | CloseCompleteMsg
  | PortalSuspendedMsg
  | EmptyQueryResponseMsg
  | ParameterDescriptionMsg (List Int)
  | NotificationMsg Notification
  | UnknownMsg Tag Bytes
%runElab derive "PGMsg" [Show, Eq]


public export
record FrameBytes where
  constructor MkFrameBytes
  tag : Bytes
  len : Bytes
  payload : Bytes
%runElab derive "FrameBytes" [Show, Eq]




public export
record StartupResult where
  constructor MkStartupResult
  authState   : Maybe PGAuthResponseTag
  params      : List ParameterStatus
  backendKey  : Maybe BackendKeyData
  ready       : Maybe ReadyForQuery
  errors      : List Error
  notices     : List Notice
-- %runElab derive "StartupResult" [Show]


public export
showStartUpResult: Maybe StartupResult -> IO()
showStartUpResult Nothing = putStrLn "No DB"
showStartUpResult (Just (MkStartupResult authState params backendKey ready errors notices)) = do
  putStrLn ("Authstate: " ++ show authState)
  putStrLn ("Params: " ++ show params)
  putStrLn ("BackendKeyData: " ++ show backendKey)
  putStrLn ("Ready: " ++ show ready)
  putStrLn ("Errors: " ++ show errors)
  putStrLn ("Notices: " ++ show notices)


public export
record QueryResult where
  constructor MkQueryResult
  description : Maybe RowDescription
  rows        : List DataRow
  commandTag  : Maybe String
  status      : Maybe ReadyForQuery
  errors      : List Error
  notices     : List Notice
%runElab derive "QueryResult" [Show]


public export
showQueryResult : QueryResult -> IO ()
showQueryResult (MkQueryResult description rows commandTag status errors notices) = do
  putStrLn ("RowDescription: " ++ show description)
  putStrLn ("Row: " ++ show rows)


public export
record PGConfig where
  constructor MkPGConfig
  host             : String
  port             : Int
  user             : String
  password         : String
  database         : String
  -- Bounds connectDB (the TCP connect plus the auth handshake) and, on a
  -- listening connection, cancelQuery's own fresh connection - see
  -- Network.Deadline for the transport deadline. DNS and CPU work are not
  -- preempted; late results are reclaimed before returning. Nothing preserves the
  -- old behavior: block indefinitely.
  connectTimeoutMs : Maybe Nat
  -- Bounds any single DB operation that waits on the server: execCommand/
  -- queryRows/queryRowsBinary/execMulti, waitForNotification, copyOut/
  -- copyIn. Nothing (the default via mkPGConfig) preserves the old
  -- behavior: block indefinitely.
  readTimeoutMs    : Maybe Nat
  -- If True, connectDB requires the connection to upgrade to TLS (Postgres's
  -- SSLRequest negotiation) and fails outright if the server doesn't
  -- support it - there's no "prefer" mode that falls back to plaintext.
  -- Requires TLS 1.3, a trusted certificate chain and SAN host/IP identity.
  useTLS           : Bool
  -- Nothing uses OpenSSL's system trust; Just selects only this PEM CA file.
  -- Supplying a CA file with useTLS=False is a configuration error.
  tlsCAFile        : Maybe String

||| Convenience constructor for the common case: no timeouts, no TLS - the
||| same behavior this client always had. Use the MkPGConfig constructor
||| (or record update syntax on a PGConfig it built) directly to set
||| connectTimeoutMs/readTimeoutMs/useTLS/tlsCAFile.
public export
mkPGConfig : (host : String) -> (port : Int) -> (user : String) -> (password : String) -> (database : String) -> PGConfig
mkPGConfig host port user password database = MkPGConfig host port user password database Nothing Nothing False Nothing

public export
record DB where
  constructor MkDB
  conn    : PGConnection Connected
  result  : Maybe StartupResult
  cfg     : PGConfig
  -- Updated after every query with the transaction status from its
  -- ReadyForQuery, so txStatus can report it without a round-trip.
  txState : IORef (Maybe TxStatus)
  -- Prepared statements from execParams, keyed by exact SQL text, so a
  -- repeated query skips re-Parse on the server. A plain association list
  -- is fine here - realistically dozens of distinct statements per
  -- connection, not thousands. No cache size cap or explicit statement
  -- cleanup (disconnect frees them all on close).
  stmtCache   : IORef (List (String, String))
  stmtCounter : IORef Int
  -- NotificationResponse can arrive interleaved with any query's own
  -- responses (Postgres's asynchronous-message rule), not just while
  -- waitForNotification is the one reading - handleQueryResponses queues
  -- one here instead of mistaking it for part of the query result it's
  -- currently assembling; waitForNotification drains this before it
  -- blocks on a fresh read.
  notifQueue  : IORef (List Notification)

  -- A timed-out or closed connection can never be reused by a pool.
  unusable : IORef Bool
