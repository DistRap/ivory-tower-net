{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Ivory.Tower.Net.Types.EtherType where

import Ivory.Language
import Ivory.Serialize

[ivory|
  bitdata EtherType :: Bits 16
    = ether_type_ipv4 as 0x0800
    | ether_type_arp  as 0x0806
    | ether_type_wol  as 0x0842
    | ether_type_ipv6 as 0x86DD
|]

wrappedEtherType :: WrappedPackRep ('Stored EtherType)
wrappedEtherType = wrapPackRep "ether_type" (repackV fromRep toRep (packRep :: PackRep ('Stored Uint16)))
instance Packable ('Stored EtherType) where
  packRep = wrappedPackRep wrappedEtherType
