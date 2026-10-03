module PropTests

-- Property-based tests (idris2-hedgehog) for postgres's hand-written
-- codecs/parsers/crypto - round-trip pairs and algebraic invariants that
-- should hold for *any* input, complementing test/src/UnitTests.idr's
-- fixed examples and RFC test vectors. See README.md's testing section.

import Hedgehog
import Data.Bits
import Data.List
import Data.Maybe
import Data.Vect
import Helper
import Crypto.SCRAM
import Crypto.ChaCha20
import Crypto.ChaCha20Poly1305
import Crypto.Curve25519
import Crypto.P256
import Data.PGValue

isLeft : Either a b -> Bool
isLeft (Left _) = True
isLeft (Right _) = False

-- Flips the low bit of the byte at `idx` - used to simulate a tampered
-- ciphertext/tag without needing a second independent byte generator.
flipBitAt : Nat -> List Bits8 -> List Bits8
flipBitAt Z     (b :: bs) = xor b 1 :: bs
flipBitAt (S k) (b :: bs) = b :: flipBitAt k bs
flipBitAt _     []        = []

-- --------------------------------------------------------------------
-- Generators
-- --------------------------------------------------------------------

bytesOfLen : Nat -> Gen (List Bits8)
bytesOfLen n = list (constant n n) anyBits8

byteRange : Gen (List Bits8)
byteRange = list (linear 0 64) anyBits8

nonEmptyByteRange : Gen (List Bits8)
nonEmptyByteRange = list (linear 1 64) anyBits8

key32 : Gen (List Bits8)
key32 = bytesOfLen 32

nonce12 : Gen (List Bits8)
nonce12 = bytesOfLen 12

int16Gen : Gen Int
int16Gen = int (linearFrom 0 (-32768) 32767)

int32Gen : Gen Int
int32Gen = int (linearFrom 0 (-2147483648) 2147483647)

-- --------------------------------------------------------------------
-- A. Wire-format integer codecs (Helper) - round trip.
-- --------------------------------------------------------------------

groupIntCodecs : Group
groupIntCodecs = MkGroup "Wire-format integer codecs round-trip"
  [ ("decodeInt16 . encodeInt16 = id", property $ do
       n <- forAll int16Gen
       decodeInt16 (encodeInt16 n) === Right (n, []))
  , ("decodeInt32 . encodeInt32 = id", property $ do
       n <- forAll int32Gen
       decodeInt32 (encodeInt32 n) === Right (n, []))
  ]

-- --------------------------------------------------------------------
-- B. Base64 (Crypto.SCRAM) - round trip.
-- --------------------------------------------------------------------

groupBase64 : Group
groupBase64 = MkGroup "Base64 round-trip"
  [ ("base64Decode . base64Encode = Just", property $ do
       bs <- forAll byteRange
       base64Decode (base64Encode bs) === Just bs)
  ]

-- --------------------------------------------------------------------
-- C. ChaCha20 (Crypto.ChaCha20) - XOR-stream self-inverse.
-- --------------------------------------------------------------------

groupChaCha20 : Group
groupChaCha20 = MkGroup "ChaCha20 stream cipher"
  [ ("encrypting twice with the same key/counter/nonce is the identity", property $ do
       key     <- forAll key32
       counter <- forAll anyBits32
       nonce   <- forAll nonce12
       pt      <- forAll byteRange
       chacha20 key counter nonce (chacha20 key counter nonce pt) === pt)
  ]

-- --------------------------------------------------------------------
-- D. ChaCha20-Poly1305 (Crypto.ChaCha20Poly1305) - AEAD round trip and
-- tamper detection.
-- --------------------------------------------------------------------

groupAEAD : Group
groupAEAD = MkGroup "ChaCha20-Poly1305 AEAD"
  [ ("decrypt undoes encrypt", property $ do
       key   <- forAll key32
       nonce <- forAll nonce12
       aad   <- forAll byteRange
       pt    <- forAll byteRange
       let (ct, tag) = encrypt key nonce aad pt
       decrypt key nonce aad ct tag === Just pt)
  , ("tampering the ciphertext is detected", property $ do
       key   <- forAll key32
       nonce <- forAll nonce12
       aad   <- forAll byteRange
       pt    <- forAll nonEmptyByteRange
       idx   <- forAll (nat (linear 0 (length pt `minus` 1)))
       let (ct, tag) = encrypt key nonce aad pt
       decrypt key nonce aad (flipBitAt idx ct) tag === Nothing)
  , ("tampering the tag is detected", property $ do
       key   <- forAll key32
       nonce <- forAll nonce12
       aad   <- forAll byteRange
       pt    <- forAll byteRange
       idx   <- forAll (nat (linear 0 15))  -- the tag is always 16 bytes
       let (ct, tag) = encrypt key nonce aad pt
       decrypt key nonce aad ct (flipBitAt idx tag) === Nothing)
  ]

-- --------------------------------------------------------------------
-- E/F. X25519 and P-256 ECDH agreement symmetry (Crypto.Curve25519,
-- Crypto.P256) - both sides of a key exchange must land on the same
-- shared secret.
-- --------------------------------------------------------------------

groupX25519 : Group
groupX25519 = MkGroup "X25519 Diffie-Hellman agreement"
  [ ("both sides compute the same shared secret", property $ do
       privA <- forAll key32
       privB <- forAll key32
       x25519 privA (x25519PublicKey privB) === x25519 privB (x25519PublicKey privA))
  ]

-- A real ECDH private key is drawn from [1, n-1] (the curve scalar
-- range excludes 0), so this excludes it too: a private key of exactly
-- 0 degenerates to the point at infinity, whose p256PublicKey encoding
-- is an empty byte string, not a well-formed peer key, so
-- p256SharedSecret correctly (and safely) returns Nothing for it rather
-- than a shared secret. That is the right behavior for an input that
-- cannot occur in practice (probability 2^-256 from a real CSPRNG), not
-- a bug to work around, so the generator excludes it instead.
-- Forces the low bit of the last byte on, guaranteeing the scalar can
-- never be exactly zero, without needing a second independent generator
-- (combining `list` and `bits8` generators in the same do-block hits an
-- Idris2/hedgehog elaboration issue - this sidesteps it).
forceLastByteOdd : List Bits8 -> List Bits8
forceLastByteOdd [x]              = [x .|. 1]
forceLastByteOdd (x :: xs@(_::_)) = x :: forceLastByteOdd xs
forceLastByteOdd []                = []

nonZeroKey32 : Gen (List Bits8)
nonZeroKey32 = map forceLastByteOdd (bytesOfLen 32)

groupP256 : Group
groupP256 = MkGroup "P-256 ECDH agreement"
  [ ("both sides compute the same shared secret", property $ do
       privA <- forAll nonZeroKey32
       privB <- forAll nonZeroKey32
       let secretAB = p256SharedSecret privA (p256PublicKey privB)
       let secretBA = p256SharedSecret privB (p256PublicKey privA)
       assert (isJust secretAB)
       secretAB === secretBA)
  ]

-- --------------------------------------------------------------------
-- G. Helper.validateFrameLength - total-domain correctness across all
-- three regions of its input (generalizes the fixed-boundary unit
-- tests in UnitTests.idr).
-- --------------------------------------------------------------------

underBoundGen : Gen Int
underBoundGen = int (linearFrom 0 (-1000) 3)

validBandGen : Gen Int
validBandGen = int (linearFrom 4 4 (4 + maxFrameBodySize))

overBoundGen : Gen Int
overBoundGen = int (linearFrom (5 + maxFrameBodySize) (5 + maxFrameBodySize) (maxFrameBodySize * 4))

groupFrameLength : Group
groupFrameLength = MkGroup "validateFrameLength total-domain correctness"
  [ ("rejects a length under the 4-byte prefix", property $ do
       msgLen <- forAll underBoundGen
       assert (isLeft (validateFrameLength msgLen)))
  , ("accepts and computes the payload size within the valid band", property $ do
       msgLen <- forAll validBandGen
       validateFrameLength msgLen === Right (msgLen - 4))
  , ("rejects a payload over the size cap", property $ do
       msgLen <- forAll overBoundGen
       assert (isLeft (validateFrameLength msgLen)))
  ]

-- --------------------------------------------------------------------
-- H. Recursive-descent parser depth limits (Data.PGJson/Data.PGValue) -
-- generalizes the two fixed-depth (50/500) examples in UnitTests.idr
-- into a property over random depth.
-- --------------------------------------------------------------------

nestedJSONArray : Nat -> String
nestedJSONArray n = pack (Data.List.replicate n '[' ++ unpack "1" ++ Data.List.replicate n ']')

nestedPGArray : Nat -> String
nestedPGArray n = pack (Data.List.replicate n '{' ++ Data.List.replicate n '}')

jsonDepthGen : Gen Nat
jsonDepthGen = frequency
  [ (1, nat (linear 0 maxJSONDepth))
  , (1, nat (linearFrom (maxJSONDepth + 1) (maxJSONDepth + 1) (maxJSONDepth + 50)))
  ]

-- parsePGArrayValue accepts one "free" outer '{' before the depth budget
-- kicks in (see Data.PGValue), so its true boundary is maxArrayDepth + 1.
arrayDepthGen : Gen Nat
arrayDepthGen = frequency
  [ (1, nat (linear 1 (maxArrayDepth + 1)))
  , (1, nat (linearFrom (maxArrayDepth + 2) (maxArrayDepth + 2) (maxArrayDepth + 51)))
  ]

groupDepthLimits : Group
groupDepthLimits = MkGroup "Recursive-descent parser depth limits"
  [ ("parseJSON accepts nesting at/under the limit, rejects over it", property $ do
       d <- forAll jsonDepthGen
       isLeft (parseJSON (nestedJSONArray d)) === (d > maxJSONDepth))
  , ("parsePGArrayValue accepts nesting at/under the limit, rejects over it", property $ do
       d <- forAll arrayDepthGen
       isLeft (parsePGArrayValue (nestedPGArray d)) === (d > maxArrayDepth + 1))
  ]

-- --------------------------------------------------------------------
-- I. Constrained JSON round trip (Data.PGJson) - the parser has no
-- existing printer, so this adds a small test-only one alongside a
-- depth-bounded generator. Deliberately conservative: numbers are
-- restricted to small integer values (sidesteps Double's show/
-- parseDouble exponent-format and NaN/Infinity edge cases) and strings
-- to alphanumeric characters (sidesteps re-deriving the parser's own
-- \uXXXX/escape rules in the printer - alphaNum text never needs
-- escaping). This is the one group that fuzzes the JSON parser with
-- generated structure, not just nesting depth.
--
-- Not attempted: an equivalent round trip for Data.PGValue's Postgres
-- array-text parser. Its quoting rule (quote exactly when an element
-- would otherwise be ambiguous with NULL, or contains a comma/brace/
-- backslash/quote/whitespace - see that parser's own module comment)
-- is delicate enough that a hastily-written test printer risks
-- encoding the test's assumptions rather than verifying the parser.
-- Group H already fuzzes that parser's depth handling.
-- --------------------------------------------------------------------

joinComma : List String -> String
joinComma []        = ""
joinComma [x]       = x
joinComma (x :: xs) = x ++ "," ++ joinComma xs

printJSON : JSONValue -> String
printJSON JNull        = "null"
printJSON (JBool b)    = if b then "true" else "false"
printJSON (JNumber d)  = show (the Integer (cast d))
printJSON (JString s)  = "\"" ++ s ++ "\""
printJSON (JArray vs)  = "[" ++ joinComma (map printJSON vs) ++ "]"
printJSON (JObject kvs) = "{" ++ joinComma (map (\(k, v) => "\"" ++ k ++ "\":" ++ printJSON v) kvs) ++ "}"

jsonKeyGen : Gen String
jsonKeyGen = string (linear 1 8) alphaNum

jsonLeafGen : Gen JSONValue
jsonLeafGen = choice
  [ pure JNull
  , map JBool bool
  , map (JNumber . cast) (int (linearFrom 0 (-1000) 1000))
  , map JString (string (linear 0 10) alphaNum)
  ]

jsonValueGen : Nat -> Gen JSONValue
jsonValueGen Z     = jsonLeafGen
jsonValueGen (S k) = frequency
  [ (3, jsonLeafGen)
  , (1, map JArray (list (linear 0 4) (jsonValueGen k)))
  , (1, map JObject (list (linear 0 4) jsonKVGen))
  ]
  where
    jsonKVGen : Gen (String, JSONValue)
    jsonKVGen = do
      key <- jsonKeyGen
      val <- jsonValueGen k
      pure (key, val)

groupJSONRoundTrip : Group
groupJSONRoundTrip = MkGroup "parseJSON round-trips a constrained generated JSONValue"
  [ ("parseJSON (printJSON v) = Right v", property $ do
       v <- forAll (jsonValueGen 3)
       parseJSON (printJSON v) === Right v)
  ]

-- --------------------------------------------------------------------

main : IO ()
main = test
  [ groupIntCodecs
  , groupBase64
  , groupChaCha20
  , groupAEAD
  , groupX25519
  , groupP256
  , groupFrameLength
  , groupDepthLimits
  , groupJSONRoundTrip
  ]
