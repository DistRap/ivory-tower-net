{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}

module Ivory.Tower.Net.Checksum (checksum) where

import Ivory.Language
import Ivory.Stdlib ((+=), when)
import Ivory.BSP.STM32.Driver.ETH (FrameBuffer)

-- | Internet checksum
checksum
  :: ( GetAlloc eff ~ 'Scope s
     , GetBreaks (AllowBreak eff) ~ 'Break
     )
  => Ref s1 FrameBuffer
  -> Uint16
  -> Sint32
  -> Ivory eff Uint16
checksum buf fromOffset len = do
  let off = toIx fromOffset
  summed <- local (ival (0 :: Uint32))
  0 `upTo` (toIx $ (len `iDiv` 2) - 1) $ \ix -> do
    a <- deref $ buf ~> stringDataL ! (off + ix * 2)
    b <- deref $ buf ~> stringDataL ! (off + ix * 2 + 1)
    summed += ((safeCast a) `iShiftL` 8 .| safeCast b)

  -- If len is odd, add remaining byte
  when
    (len .% 2 ==? 1)
    $ do
        e <- deref $ buf ~> stringDataL ! (off + toIx len - 1)
        summed += (safeCast e `iShiftL` 8)

  forever $ do
    c <- deref summed
    when (c `iShiftR` 16 ==? 0) breakOut
    store summed $ (c .& 0xFFFF) + (c `iShiftR` 16)

  deref summed
    >>= pure . bitCast . iComplement
