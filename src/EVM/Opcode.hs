{-# LANGUAGE PatternSynonyms #-}

-- |
-- Module: EVM.Opcode
-- Copyright: 2018-2022 Simon Shine
-- Maintainer: Simon Shine <simon@simonshine.dk>
-- License: MIT
--
-- This module exposes the 'Opcode' type for expressing Ethereum VM opcodes
-- as extracted from the Ethereum Yellow Paper with amendments from various
-- EIPs. The Yellow Paper is available at:
--
-- https://ethereum.github.io/yellowpaper/paper.pdf
--
-- The list of opcodes is found in appendix H.2.
--
-- But it is not always up-to-date, so keeping track of EIPs that add or
-- modify instructions is necessary. See comments in this module for the
-- references to these additions.
module EVM.Opcode
  ( -- * Types
    Opcode,
    Opcode' (..),
    OpcodeSpec (..),
    opcodeSpec,

    -- ** Pseudo-instructions and helper functions
    jump,
    jumpi,
    jumpdest,
    -- Extraction
    jumpAnnot,
    jumpdestAnnot,

    -- ** Conversion and printing
    concrete,
    opcodeText,
    opcodeSize,
    toHex,
    pack,
    toBytes,

    -- ** Parse and validate instructions
    readDUP,
    readSWAP,
    readLOG,
    readPUSH,
    readOp,
    readOps,

    -- ** Pattern synonyms
    pattern DUP1,
    pattern DUP2,
    pattern DUP3,
    pattern DUP4,
    pattern DUP5,
    pattern DUP6,
    pattern DUP7,
    pattern DUP8,
    pattern DUP9,
    pattern DUP10,
    pattern DUP11,
    pattern DUP12,
    pattern DUP13,
    pattern DUP14,
    pattern DUP15,
    pattern DUP16,
    pattern SWAP1,
    pattern SWAP2,
    pattern SWAP3,
    pattern SWAP4,
    pattern SWAP5,
    pattern SWAP6,
    pattern SWAP7,
    pattern SWAP8,
    pattern SWAP9,
    pattern SWAP10,
    pattern SWAP11,
    pattern SWAP12,
    pattern SWAP13,
    pattern SWAP14,
    pattern SWAP15,
    pattern SWAP16,
    pattern LOG0,
    pattern LOG1,
    pattern LOG2,
    pattern LOG3,
    pattern LOG4,
  )
where

import Control.Applicative (Alternative (many), (<|>))
import Control.Monad (guard, replicateM)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.DoubleWord (Word256, fromHiAndLo)
import Data.Either (fromRight)
import qualified Data.List as List
import Data.Serialize.Get (Get, getWord64be, getWord8, runGet)
import Data.String (IsString, fromString)
import Data.Text (Text)
import Data.Word (Word64, Word8)
import EVM.Opcode.Internal
import Text.Printf (printf)
import Prelude hiding (EQ, GT, LT)

-- | An 'Opcode' is a plain, parameterless Ethereum VM Opcode.
type Opcode = Opcode' ()

-- | 'jump' is a plain parameterless 'Opcode'.
jump :: Opcode
jump = JUMP ()

-- | 'jumpi' is a plain parameterless 'Opcode'.
jumpi :: Opcode
jumpi = JUMPI ()

-- | 'jumpdest' is a plain parameterless 'Opcode'.
jumpdest :: Opcode
jumpdest = JUMPDEST ()

-- | Read a 'DUP' opcode ('DUP1' -- 'DUP16') safely.
readDUP :: Get Opcode
readDUP = do
  b <- getWord8
  guard $ b >= 0x80 && b <= 0x8f
  pure $ DUP $ fromWord8 $ b - 0x80

-- | Read a 'SWAP' opcode ('SWAP1' -- 'SWAP16') safely.
readSWAP :: Get Opcode
readSWAP = do
  b <- getWord8
  guard $ b >= 0x90 && b <= 0x9f
  pure $ SWAP $ fromWord8 $ b - 0x90

-- | Read a 'LOG' opcode ('LOG1' -- 'LOG4') safely.
readLOG :: Get Opcode
readLOG = do
  b <- getWord8
  guard $ b >= 0xa0 && b <= 0xa4
  pure $ LOG $ fromWord8 $ b - 0xa0

-- | Read a 'PUSH' opcode safely.
readPUSH :: Get Opcode
readPUSH = do
  b <- getWord8
  guard $ b >= 0x60 && b <= 0x7f
  let n = fromIntegral $ b - 0x60 + 1
  bs <- replicateM n getWord8
  pure $ PUSH $ word256 bs

readOps :: ByteString -> Either String [Opcode]
readOps = runGet (many readOp)

-- | Parse an 'Opcode' from a 'Word8'. In case of 'PUSH' instructions, read the
-- constant being pushed from a subsequent 'ByteString'.
readOp :: Get Opcode
readOp =
  readDUP
    <|> readSWAP
    <|> readLOG
    <|> readPUSH
    <|> simple
  where
    simple = do
      word <- getWord8
      case word of
        -- 0s: Stop and Arithmetic Operations
        0x00 -> pure STOP
        0x01 -> pure ADD
        0x02 -> pure MUL
        0x03 -> pure SUB
        0x04 -> pure DIV
        0x05 -> pure SDIV
        0x06 -> pure MOD
        0x07 -> pure SMOD
        0x08 -> pure ADDMOD
        0x09 -> pure MULMOD
        0x0a -> pure EXP
        0x0b -> pure SIGNEXTEND
        -- 10s: Comparison & Bitwise Logic Operations
        0x10 -> pure LT
        0x11 -> pure GT
        0x12 -> pure SLT
        0x13 -> pure SGT
        0x14 -> pure EQ
        0x15 -> pure ISZERO
        0x16 -> pure AND
        0x17 -> pure OR
        0x18 -> pure XOR
        0x19 -> pure NOT
        0x1a -> pure BYTE
        0x1b -> pure SHL
        0x1c -> pure SHR
        0x1d -> pure SAR
        -- 20s: SHA3
        0x20 -> pure SHA3
        -- 30s: Environmental Information
        0x30 -> pure ADDRESS
        0x31 -> pure BALANCE
        0x32 -> pure ORIGIN
        0x33 -> pure CALLER
        0x34 -> pure CALLVALUE
        0x35 -> pure CALLDATALOAD
        0x36 -> pure CALLDATASIZE
        0x37 -> pure CALLDATACOPY
        0x38 -> pure CODESIZE
        0x39 -> pure CODECOPY
        0x3a -> pure GASPRICE
        0x3b -> pure EXTCODESIZE
        0x3c -> pure EXTCODECOPY
        0x3d -> pure RETURNDATASIZE
        0x3e -> pure RETURNDATACOPY
        0x3f -> pure EXTCODEHASH
        -- 40s: Block Information
        0x40 -> pure BLOCKHASH
        0x41 -> pure COINBASE
        0x42 -> pure TIMESTAMP
        0x43 -> pure NUMBER
        0x44 -> pure DIFFICULTY
        0x45 -> pure GASLIMIT
        0x46 -> pure CHAINID
        0x47 -> pure SELFBALANCE
        -- 50s: Stack, Memory, Storage and Flow Operations
        0x50 -> pure POP
        0x51 -> pure MLOAD
        0x52 -> pure MSTORE
        0x53 -> pure MSTORE8
        0x54 -> pure SLOAD
        0x55 -> pure SSTORE
        0x56 -> pure jump
        0x57 -> pure jumpi
        0x58 -> pure PC
        0x59 -> pure MSIZE
        0x5a -> pure GAS
        0x5b -> pure jumpdest
        -- f0s: System Operations
        0xf0 -> pure CREATE
        0xf1 -> pure CALL
        0xf2 -> pure CALLCODE
        0xf3 -> pure RETURN
        0xf4 -> pure DELEGATECALL
        0xf5 -> pure CREATE2
        0xfa -> pure STATICCALL
        0xfd -> pure REVERT
        0xfe -> pure INVALID
        0xff -> pure SELFDESTRUCT
        -- Unknown
        x -> pure $ UNKNOWN x

-- | Get a 'Word256' from a 'ByteString'
--
-- Pads the ByteString with NULs up to 32 bytes.
word256 :: [Word8] -> Word256
word256 = getWord256 . padLeft 32
  where
    getWord256 :: ByteString -> Word256
    getWord256 =
      fromRight (error "padded; qed;")
        . runGet
          ( fromWord64s
              <$> getWord64be
              <*> getWord64be
              <*> getWord64be
              <*> getWord64be
          )

    fromWord64s :: Word64 -> Word64 -> Word64 -> Word64 -> Word256
    fromWord64s a b c d = fromHiAndLo (fromHiAndLo a b) (fromHiAndLo c d)

    padLeft :: Int -> [Word8] -> ByteString
    padLeft n xs = BS.pack $ replicate (n - length xs) 0 <> xs

-- | Show 'Opcode' as 'Text'.
opcodeText :: Opcode -> Text
opcodeText = opcodeName . opcodeSpec

-- | Calculate the size in bytes of an encoded opcode. The only 'Opcode'
-- that uses more than one byte is 'PUSH'. Sizes are trivially determined
-- for only 'Opcode' with unlabelled jumps, since we cannot know e.g. where
-- the label of a 'EVM.Opcode.LabelledOpcode' points to before code generation
-- has completed.
opcodeSize :: Num i => Opcode -> i
opcodeSize (PUSH n) = List.genericLength . uncurry (:) $ push' n
opcodeSize _opcode = 1

-- | Convert a @['Opcode']@ to a string of ASCII hexadecimals.
toHex :: IsString s => [Opcode] -> s
toHex = fromString . List.concatMap (printf "%02x") . List.concatMap toBytes

-- | Convert a @['Opcode']@ to bytecode.
pack :: [Opcode] -> ByteString
pack = BS.pack . List.concatMap toBytes

-- | Convert an @'Opcode'@ to a @['Word8']@.
--
-- To convert many 'Opcode's to bytecode, use 'pack'.
toBytes :: Opcode -> [Word8]
toBytes (PUSH n) = uncurry (:) (push' n)
toBytes opcode = [opcodeEncoding (opcodeSpec opcode)]
