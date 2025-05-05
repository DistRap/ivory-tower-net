{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Ivory.Tower.Net.Types.TCP where

import Ivory.Language
import Ivory.Serialize

[ivory|
  bitdata TCPDataOffset :: Bits 8 = tcpDataOffset
    { tcp_data_offset_value :: Bits 4 -- ^ Data offset
    , _                     :: Bits 4 -- ^ (Reserved)
    }

  bitdata TCPFlags :: Bits 8 = tcpFlags
    { tcp_flags_cwr :: Bit -- ^ Congestion window reduced
    , tcp_flags_ece :: Bit -- ^ ECN-Echo
    , tcp_flags_urg :: Bit -- ^ Urgency bit
    , tcp_flags_ack :: Bit -- ^ Acknowledgment field is significant
    , tcp_flags_psh :: Bit -- ^ Push notification
    , tcp_flags_rst :: Bit -- ^ Reset connection
    , tcp_flags_syn :: Bit -- ^ Synchronize sequence numbers
    , tcp_flags_fin :: Bit -- ^ Last packet from sender
    }

  bitdata TCPOption :: Bits 8
    = tcp_option_end          as 0 -- ^ End of option list
    | tcp_option_nop          as 1 -- ^ No operation
    | tcp_option_mss          as 2 -- ^ Maximum segment size (opt length 4)
    | tcp_option_ws           as 3 -- ^ Window size (opt length 3)
    | tcp_option_sack_allowed as 4 -- ^ SACK permitted (opt length 2)
    | tcp_option_sack         as 5 -- ^ Selective ACKnowledgement (opt length (or) 10, 18, 26, 34)
    | tcp_option_timestamp    as 8 -- ^ Timestamp and echo of previous timestamp (opt length 10)
|]

wrappedTCPDataOffset :: WrappedPackRep ('Stored TCPDataOffset)
wrappedTCPDataOffset =  wrapPackRep "tcp_data_offset" (repackV fromRep toRep (packRep :: PackRep ('Stored Uint8)))
instance Packable ('Stored TCPDataOffset) where
  packRep = wrappedPackRep wrappedTCPDataOffset

wrappedTCPFlags :: WrappedPackRep ('Stored TCPFlags)
wrappedTCPFlags =  wrapPackRep "tcp_flags" (repackV fromRep toRep (packRep :: PackRep ('Stored Uint8)))
instance Packable ('Stored TCPFlags) where
  packRep = wrappedPackRep wrappedTCPFlags
