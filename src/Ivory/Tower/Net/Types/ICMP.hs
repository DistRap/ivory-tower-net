{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Ivory.Tower.Net.Types.ICMP where

import Ivory.Language
import Ivory.Serialize

[ivory|
  -- Operation
  bitdata IcmpType :: Bits 8
    = icmp_echo_reply   as 0
    | icmp_unreachable  as 3
    | icmp_echo_request as 8
|]

wrappedIcmpType :: WrappedPackRep ('Stored IcmpType)
wrappedIcmpType = wrapPackRep "icmp_type" (repackV fromRep toRep (packRep :: PackRep ('Stored Uint8)))
instance Packable ('Stored IcmpType) where
  packRep = wrappedPackRep wrappedIcmpType
