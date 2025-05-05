{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Ivory.Tower.Net.Types.ARP where

import Ivory.Language
import Ivory.Serialize

[ivory|
  -- Operation
  bitdata ArpOp :: Bits 16
    = arp_op_request as 1
    | arp_op_reply   as 2

  -- Hardware type
  bitdata ArpHwType :: Bits 16
    = arp_hw_type_ethernet as 0x0001

  -- Hardware address length (MAC length)
  bitdata ArpHwLength :: Bits 8
    = arp_hw_length_default as 6

  -- Protocol address length (IP length)
  bitdata ArpProtoLength :: Bits 8
    = arp_proto_length_ipv4 as 4
    | arp_proto_length_ipv6 as 16
|]

wrappedArpOp :: WrappedPackRep ('Stored ArpOp)
wrappedArpOp =  wrapPackRep "arp_op" (repackV fromRep toRep (packRep :: PackRep ('Stored Uint16)))
instance Packable ('Stored ArpOp) where
  packRep = wrappedPackRep wrappedArpOp

wrappedArpHwType :: WrappedPackRep ('Stored ArpHwType)
wrappedArpHwType = wrapPackRep "arp_hw_type" (repackV fromRep toRep (packRep :: PackRep ('Stored Uint16)))
instance Packable ('Stored ArpHwType) where
  packRep = wrappedPackRep wrappedArpHwType

wrappedArpHwLength :: WrappedPackRep ('Stored ArpHwLength)
wrappedArpHwLength = wrapPackRep "arp_hw_length" (repackV fromRep toRep (packRep :: PackRep ('Stored Uint8)))
instance Packable ('Stored ArpHwLength) where
  packRep = wrappedPackRep wrappedArpHwLength

wrappedArpProtoLength :: WrappedPackRep ('Stored ArpProtoLength)
wrappedArpProtoLength = wrapPackRep "arp_proto_length" (repackV fromRep toRep (packRep :: PackRep ('Stored Uint8)))
instance Packable ('Stored ArpProtoLength) where
  packRep = wrappedPackRep wrappedArpProtoLength
