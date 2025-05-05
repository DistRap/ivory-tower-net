{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Ivory.Tower.Net.Types.IP where

import Ivory.Language
import Ivory.Serialize

[ivory|
  bitdata IPVersionIHL :: Bits 8
    = ip_version_ihl_4_20 as 0x45 -- ^ IPv4, 20 bytes header length

  bitdata IPFlags :: Bits 3 = ipFlags
    { ip_flags_reserved :: Bit -- (Reserved)
    , ip_flags_df       :: Bit -- ^ Don't fragment
    , ip_flags_mf       :: Bit -- ^ More fragments
    }

  bitdata IPProtocol :: Bits 8
    = ip_protocol_icmp as 1  -- ^ Internet Control Message Protocol
    | ip_protocol_tcp  as 6  -- ^ Transmission Control Protocol
    | ip_protocol_udp  as 17 -- ^ User Datagram Protocol
|]

wrappedIPVersionIHL :: WrappedPackRep ('Stored IPVersionIHL)
wrappedIPVersionIHL =  wrapPackRep "ip_version_ihl" (repackV fromRep toRep (packRep :: PackRep ('Stored Uint8)))
instance Packable ('Stored IPVersionIHL) where
  packRep = wrappedPackRep wrappedIPVersionIHL

wrappedIPProtocol :: WrappedPackRep ('Stored IPProtocol)
wrappedIPProtocol =  wrapPackRep "ip_protocol" (repackV fromRep toRep (packRep :: PackRep ('Stored Uint8)))
instance Packable ('Stored IPProtocol) where
  packRep = wrappedPackRep wrappedIPProtocol
