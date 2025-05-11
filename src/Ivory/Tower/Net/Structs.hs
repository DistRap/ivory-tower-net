{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TypeFamilies #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Ivory.Tower.Net.Structs where

import Ivory.Tower.Net.Types.ARP
import Ivory.Tower.Net.Types.EtherType
import Ivory.Tower.Net.Types.ICMP
import Ivory.Tower.Net.Types.IP
import Ivory.Tower.Net.Types.TCP

import Ivory.Language
import Ivory.Serialize
import Ivory.Tower
import Ivory.BSP.STM32.Driver.ETH (FrameBuffer, ethModule)

-- * Offset & lengths

ethHeaderLength :: Uint16
ethHeaderLength = 14
ethOffset :: Uint16
ethOffset = ethHeaderLength

ipHeaderLength :: Uint16
ipHeaderLength = 20

ipOffset :: Uint16
ipOffset = ethOffset + ipHeaderLength

ipPseudoHeaderLength :: Uint16
ipPseudoHeaderLength = 12

udpHeaderLength :: Uint16
udpHeaderLength = 8

udpOffset :: Uint16
udpOffset = ipOffset + udpHeaderLength

-- ** Checksum offsets

icmpChecksumOffset :: Uint16
icmpChecksumOffset = ipOffset + 2

ipChecksumOffset :: Uint16
ipChecksumOffset = ethOffset + 10

udpChecksumOffset :: Uint16
udpChecksumOffset = ipOffset + 6

-- * Structs

[ivory|
  struct eth_header
  { eth_header_target_mac :: Array 6 (Stored Uint8)
  ; eth_header_source_mac :: Array 6 (Stored Uint8)
  ; eth_header_eth_type   :: Stored EtherType
  }

  struct ip_header
  { ip_header_version_ihl       :: Stored IPVersionIHL -- ^ Combined version and Internet Header Length
  ; ip_header_dscp_ecn          :: Stored Uint8        -- ^ QOS
  ; ip_header_total_length      :: Stored Uint16
  ; ip_header_ident             :: Stored Uint16
  ; ip_header_flags_frag_offset :: Stored Uint16       -- ^ Fragmentation info (3 bits of IPFlags, 13 bits fragment offset)
  ; ip_header_ttl               :: Stored Uint8        -- ^ Time to live
  ; ip_header_protocol          :: Stored IPProtocol
  ; ip_header_checksum          :: Stored Uint16
  ; ip_header_source_address    :: Array 4 (Stored Uint8)
  ; ip_header_target_address    :: Array 4 (Stored Uint8)
  }

  struct ip_pseudo_header
  { ip_pseudo_header_source_address :: Array 4 (Stored Uint8)
  ; ip_pseudo_header_target_address :: Array 4 (Stored Uint8)
  ; ip_pseudo_header_zeros          :: Stored Uint8
  ; ip_pseudo_header_protocol       :: Stored IPProtocol
  ; ip_pseudo_header_length         :: Stored Uint16
  }

  struct udp_header
  { udp_header_source_port :: Stored Uint16
  ; udp_header_target_port :: Stored Uint16
  ; udp_header_length      :: Stored Uint16
  ; udp_header_checksum    :: Stored Uint16
  }

  struct tcp_header
  { tcp_header_source_port    :: Stored Uint16
  ; tcp_header_target_port    :: Stored Uint16
  ; tcp_header_seq_num        :: Stored Uint32
  ; tcp_header_ack_num        :: Stored Uint32
  ; tcp_header_data_offset    :: Stored TCPDataOffset
  ; tcp_header_flags          :: Stored TCPFlags
  ; tcp_header_window         :: Stored Uint16
  ; tcp_header_checksum       :: Stored Uint16
  ; tcp_header_urgent_pointer :: Stored Uint16
  ; tcp_header_options        :: Array 40 (Stored Uint8)
  }

  struct arp_packet
  { arp_packet_hw_type    :: Stored ArpHwType
  ; arp_packet_proto_type :: Stored EtherType
  ; arp_hw_length         :: Stored ArpHwLength
  ; arp_proto_length      :: Stored ArpProtoLength
  ; arp_op                :: Stored ArpOp
  ; arp_sender_hw_addr    :: Array 6 (Stored Uint8)
  ; arp_sender_proto_addr :: Array 4 (Stored Uint8)
  ; arp_target_hw_addr    :: Array 6 (Stored Uint8)
  ; arp_target_proto_addr :: Array 4 (Stored Uint8)
  }

  struct icmp_packet
  { icmp_packet_type     :: Stored IcmpType
  ; icmp_packet_code     :: Stored Uint8
  ; icmp_packet_checksum :: Stored Uint16
  }

  -- ARP table entry
  struct arp_entry
  { arp_entry_valid      :: Stored IBool
  ; arp_entry_hw_addr    :: Array 6 (Stored Uint8)
  ; arp_entry_proto_addr :: Array 4 (Stored Uint8)
  }

  -- Interface
  struct udp_rx
  { udp_rx_port      :: Stored Uint16
  ; udp_rx_data      :: FrameBuffer
  }

  struct udp_tx
  { udp_tx_ip   :: Array 4 (Stored Uint8)
  ; udp_tx_port :: Stored Uint16
  ; udp_tx_data :: FrameBuffer
  }
|]

-- * Module

netModule :: Module
netModule = package "eth_structs" $ do
  defStruct (Proxy :: Proxy "eth_header")
  defStruct (Proxy :: Proxy "ip_header")
  defStruct (Proxy :: Proxy "ip_pseudo_header")
  defStruct (Proxy :: Proxy "udp_header")
  defStruct (Proxy :: Proxy "tcp_header")
  defStruct (Proxy :: Proxy "arp_packet")
  defStruct (Proxy :: Proxy "icmp_packet")

  defStruct (Proxy :: Proxy "arp_entry")

  defStruct (Proxy :: Proxy "udp_rx")
  defStruct (Proxy :: Proxy "udp_tx")

  depend ethModule
  depend serializeModule

  wrappedPackMod ethStructWrapper
  wrappedPackMod wrappedEtherType

  wrappedPackMod ipStructWrapper
  wrappedPackMod wrappedIPVersionIHL
  wrappedPackMod wrappedIPProtocol

  wrappedPackMod ipPseudoStructWrapper

  wrappedPackMod udpStructWrapper

  wrappedPackMod tcpStructWrapper
  wrappedPackMod wrappedTCPDataOffset
  wrappedPackMod wrappedTCPFlags

  wrappedPackMod arpStructWrapper
  wrappedPackMod wrappedArpOp
  wrappedPackMod wrappedArpHwType
  wrappedPackMod wrappedArpHwLength
  wrappedPackMod wrappedArpProtoLength

  wrappedPackMod icmpStructWrapper
  wrappedPackMod wrappedIcmpType

netTowerDeps :: Tower e ()
netTowerDeps = do
  towerDepends netModule
  towerModule netModule

  mapM_ towerArtifact serializeArtifacts
  towerDepends serializeModule
  towerModule serializeModule

-- * Wrappers

ethStructWrapper :: WrappedPackRep ('Struct "eth_header")
ethStructWrapper = wrapPackRep "eth_header" $ packStruct
  [ packLabel eth_header_target_mac
  , packLabel eth_header_source_mac
  , packLabel eth_header_eth_type
  ]

ipStructWrapper :: WrappedPackRep ('Struct "ip_header")
ipStructWrapper = wrapPackRep "ip_header" $ packStruct
  [ packLabel ip_header_version_ihl
  , packLabel ip_header_dscp_ecn
  , packLabel ip_header_total_length
  , packLabel ip_header_ident
  , packLabel ip_header_flags_frag_offset
  , packLabel ip_header_ttl
  , packLabel ip_header_protocol
  , packLabel ip_header_checksum
  , packLabel ip_header_source_address
  , packLabel ip_header_target_address
  ]

ipPseudoStructWrapper :: WrappedPackRep ('Struct "ip_pseudo_header")
ipPseudoStructWrapper = wrapPackRep "ip_pseudo_header" $ packStruct
  [ packLabel ip_pseudo_header_source_address
  , packLabel ip_pseudo_header_target_address
  , packLabel ip_pseudo_header_zeros
  , packLabel ip_pseudo_header_protocol
  , packLabel ip_pseudo_header_length
  ]

udpStructWrapper :: WrappedPackRep ('Struct "udp_header")
udpStructWrapper = wrapPackRep "udp_header" $ packStruct
  [ packLabel udp_header_source_port
  , packLabel udp_header_target_port
  , packLabel udp_header_length
  , packLabel udp_header_checksum
  ]

tcpStructWrapper :: WrappedPackRep ('Struct "tcp_header")
tcpStructWrapper = wrapPackRep "tcp_header" $ packStruct
  [ packLabel tcp_header_source_port
  , packLabel tcp_header_target_port
  , packLabel tcp_header_seq_num
  , packLabel tcp_header_ack_num
  , packLabel tcp_header_data_offset
  , packLabel tcp_header_flags
  , packLabel tcp_header_window
  , packLabel tcp_header_checksum
  , packLabel tcp_header_urgent_pointer
  , packLabel tcp_header_options
  ]

arpStructWrapper :: WrappedPackRep ('Struct "arp_packet")
arpStructWrapper = wrapPackRep "arp_packet" $ packStruct
  [ packLabel arp_packet_hw_type
  , packLabel arp_packet_proto_type
  , packLabel arp_hw_length
  , packLabel arp_proto_length
  , packLabel arp_op
  , packLabel arp_sender_hw_addr
  , packLabel arp_sender_proto_addr
  , packLabel arp_target_hw_addr
  , packLabel arp_target_proto_addr
  ]

icmpStructWrapper :: WrappedPackRep ('Struct "icmp_packet")
icmpStructWrapper = wrapPackRep "icmp_packet" $ packStruct
  [ packLabel icmp_packet_type
  , packLabel icmp_packet_code
  , packLabel icmp_packet_checksum
  ]

-- * Packable instances

instance Packable ('Struct "eth_header") where
  packRep = wrappedPackRep ethStructWrapper

instance Packable ('Struct "ip_header") where
  packRep = wrappedPackRep ipStructWrapper

instance Packable ('Struct "ip_pseudo_header") where
  packRep = wrappedPackRep ipPseudoStructWrapper

instance Packable ('Struct "udp_header") where
  packRep = wrappedPackRep udpStructWrapper

instance Packable ('Struct "tcp_header") where
  packRep = wrappedPackRep tcpStructWrapper

instance Packable ('Struct "arp_packet") where
  packRep = wrappedPackRep arpStructWrapper

instance Packable ('Struct "icmp_packet") where
  packRep = wrappedPackRep icmpStructWrapper
