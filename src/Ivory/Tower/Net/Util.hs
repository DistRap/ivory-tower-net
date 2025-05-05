{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Ivory.Tower.Net.Util
  ( arrayEq
  , ipToList
  , macToList
  ) where

import Ivory.Language
import Ivory.Stdlib (unless)
import GHC.TypeNats (KnownNat)
import qualified Numeric

arrayEq
  :: ( GetAlloc eff ~ Scope s
     , KnownNat len
     , IvoryStore a
     , KnownConstancy c1
     , KnownConstancy c2
     , IvoryEq a
     )
  => Pointer Valid c1 s1 (Array len (Stored a))
  -> Pointer Valid c2 s2 (Array len (Stored a))
  -> Ivory eff IBool
arrayEq a b = do
  isEq <- local $ ival true
  arrayMap $ \ix -> do
    ax <- deref (a ! ix)
    bx <- deref (b ! ix)
    unless
      (ax ==? bx)
      $ store isEq false

  deref isEq >>= pure

macToList :: String -> [Uint8]
macToList "" = []
macToList x =
  case break (==':') x of
    (w, []) -> pure $ fromIntegral $ readHex' w
    (w, x') -> (fromIntegral $ readHex' w) : macToList (tail x')
  where
    readHex' :: String -> Int
    readHex' s =
      case Numeric.readHex s of
        [(num, "")] -> num
        _           -> error $ "Invalid MAC address"

ipToList :: String -> [Uint8]
ipToList "" = []
ipToList x =
  case break (=='.') x of
    (w, []) -> pure $ (fromIntegral :: Int -> Uint8) $ read w
    (w, x') -> ((fromIntegral :: Int -> Uint8) $ read w) : ipToList (tail x')
