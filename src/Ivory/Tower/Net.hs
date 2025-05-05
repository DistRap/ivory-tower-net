{-# LANGUAGE DataKinds #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Ivory.Tower.Net
  ( netTower
  , module Ivory.Tower.Net.Types
  ) where

import Ivory.Language
import Ivory.Stdlib
import Ivory.Tower
import Ivory.Tower.HAL.Bus.Interface (BackpressureTransmit(..))
import Ivory.BSP.STM32.Driver.ETH (FrameBuffer)

import Ivory.Tower.Net.Types
import Ivory.Serialize

netTower
  :: NetConfig
  -> ( ChanOutput ('Stored IBool)
     , BackpressureTransmit FrameBuffer ('Stored IBool)
     , ChanOutput (Struct "rx_packet")
     )
  -> Tower
       e
       ( ChanOutput (Struct "udp_packet")
       )
netTower NetConfig{..} (ready, BackpressureTransmit txReq _txDone, rxDone) = do
  netTowerDeps

  arpResolve <- channel
  udp <- channel

  monitor "net" $ do
    ethReady <- state "ethReady"
    txCounter <- stateInit "txCounter" (ival (0 :: Uint8))

    lastRx <- state "lastRx"
    rxCounter <- stateInit "rxCounter" (ival (0 :: Uint8))

    (macAddr :: Ref Global (Array 6 (Stored Uint8))) <-
      stateInit
        "macAddr"
        (iarray $ map ival $ unMACAddress netConfigMACAddress)

    (ipAddr :: Ref Global (Array 4 (Stored Uint8))) <-
      stateInit
        "ipAddr"
        (iarray $ map ival $ unIPAddress netConfigIPAddress)

    (decodedHeader :: Ref Global (Struct "eth_header")) <-
      state "decodedHeader"
    (decodedARP :: Ref Global (Struct "arp_packet")) <-
      state "decodedARP"
    (decodedIP :: Ref Global (Struct "ip_header")) <-
      state "decodedIP"
    (decodedICMP :: Ref Global (Struct "icmp_packet")) <-
      state "decodedICMP"
    (decodedUDP :: Ref Global (Struct "udp_header")) <-
      state "decodedUDP"

    (arpTable :: Ref Global (Array 10 (Struct "arp_entry"))) <-
      state "arpTable"

    arpTableFull <- state "arpTableFull"
    invalidUDPs <- stateInit "invalidUDPs" (ival (0 :: Uint32))

    -- use states instead of allocating on stack
    arpReq <- state "arpReq"
    arpRep <- state "arpRep"
    udpRep <- state "udpRep"

    handler ready "ethReady" $ do
      callback $ const $ store ethReady true

    handler (snd arpResolve) "arpResolve" $ do
      txE <- emitter txReq 1
      callback $ \query -> do
        (bcastMac :: Ref s (Array 6 (Stored Uint8))) <-
          local (iarray $ map ival $ macToList "FF:FF:FF:FF:FF:FF")
        ethHeader <- local
            $ istruct [ eth_header_eth_type .= ival ether_type_arp ]

        refCopy (ethHeader ~> eth_header_target_mac) bcastMac
        refCopy (ethHeader ~> eth_header_source_mac) macAddr
        packInto (arpReq ~> stringDataL) 0 (constRef ethHeader)
        arpPayload <- local
            $ istruct
                [ arp_packet_hw_type    .= ival arp_hw_type_ethernet
                , arp_packet_proto_type .= ival ether_type_ipv4
                , arp_hw_length         .= ival arp_hw_length_default
                , arp_proto_length      .= ival arp_proto_length_ipv4
                , arp_op                .= ival arp_op_request
                , arp_target_proto_addr .=
                    (iarray $ map ival $ ipToList "192.168.192.1")
                ]

        refCopy (arpPayload ~> arp_sender_hw_addr) macAddr
        refCopy (arpPayload ~> arp_sender_proto_addr) ipAddr
        refCopy (arpPayload ~> arp_target_proto_addr) query

        packInto
          (arpReq ~> stringDataL)
          (safeCast ethOffset)
          (constRef arpPayload)
        store (arpReq ~> stringLengthL) 42

        txCounter += 1
        emit txE (constRef arpReq)

    handler rxDone "rx" $ do
      udpE <- emitter (fst udp) 1
      txE <- emitter txReq 1
      callback $ \rx -> do
        rxCounter += 1
        refCopy lastRx rx
        let buf = rx ~> rx_packet_buffer ~> stringDataL

        unpackFrom buf 0 decodedHeader

        headerType <- decodedHeader ~>* eth_header_eth_type
        cond_
          [ headerType ==? ether_type_arp ==> do
              unpackFrom buf (safeCast ethOffset) decodedARP

              arpOp <- decodedARP ~>* arp_op
              cond_
                [ arpOp ==? arp_op_reply ==> do
                    merge <- local izero
                    -- arpLookup
                    arrayMap $ \ix -> do
                      valid <- (arpTable ! ix) ~>* arp_entry_valid
                      when valid $ do
                        protoEq <- arrayEq
                          ((arpTable ! ix) ~> arp_entry_proto_addr)
                          (decodedARP ~> arp_sender_proto_addr)
                        when
                          protoEq
                          $ do
                              store merge true
                              -- Update hardware address
                              refCopy
                                ((arpTable ! ix) ~> arp_entry_hw_addr)
                                (decodedARP ~> arp_sender_hw_addr)
                              breakOut

                    merged <- deref merge
                    unless merged $ do
                      inserted <- local izero
                      arrayMap $ \ix -> do
                        valid <- (arpTable ! ix) ~>* arp_entry_valid
                        -- Unused entry
                        when (iNot valid) $ do
                          refCopy
                            ((arpTable ! ix) ~> arp_entry_hw_addr)
                            (decodedARP ~> arp_sender_hw_addr)
                          refCopy
                            ((arpTable ! ix) ~> arp_entry_proto_addr)
                            (decodedARP ~> arp_sender_proto_addr)
                          store inserted true
                          breakOut

                      okay <- deref inserted
                      unless
                        okay
                        $ do
                            store arpTableFull true
                            comment "ARP table full"
                            assert okay

                , arpOp ==? arp_op_request ==> do
                    ethHeader <- local
                        $ istruct [ eth_header_eth_type .= ival ether_type_arp ]

                    refCopy
                      (ethHeader ~> eth_header_target_mac)
                      (decodedHeader ~> eth_header_source_mac)
                    refCopy
                      (ethHeader ~> eth_header_source_mac)
                      macAddr

                    packInto (arpRep ~> stringDataL) 0 (constRef ethHeader)
                    arpPayload <- local
                        $ istruct
                            [ arp_packet_hw_type    .= ival arp_hw_type_ethernet
                            , arp_packet_proto_type .= ival ether_type_ipv4
                            , arp_hw_length         .= ival arp_hw_length_default
                            , arp_proto_length      .= ival arp_proto_length_ipv4
                            , arp_op                .= ival arp_op_reply
                            ]
                    refCopy
                      (arpPayload ~> arp_target_proto_addr)
                      (decodedARP ~> arp_sender_proto_addr)
                    refCopy
                      (arpPayload ~> arp_target_hw_addr)
                      (decodedARP ~> arp_sender_hw_addr)

                    refCopy (arpPayload ~> arp_sender_hw_addr) macAddr
                    refCopy (arpPayload ~> arp_sender_proto_addr) ipAddr

                    packInto
                      (arpRep ~> stringDataL)
                      (safeCast ethOffset)
                      (constRef arpPayload)
                    store (arpRep ~> stringLengthL) 42
                    emit txE (constRef arpRep)
                ]
          , headerType ==? ether_type_ipv4 ==> do
              unpackFrom buf (safeCast ethOffset) decodedIP

              ipValid <- checksum
                (lastRx ~> rx_packet_buffer)
                ethOffset
                (safeCast ipHeaderLength)

              comment "IP Checksum"
              assert (ipValid ==? 0x0)

              ipProto <- decodedIP ~>* ip_header_protocol
              verIhl <- decodedIP ~>* ip_header_version_ihl

              when
                -- we only handle IPv4 w/o any options,
                -- ihl <- (.| 0x0F) . toRep <$> decodedIP ~>* ip_header_version_ihl
                (verIhl ==? ip_version_ihl_4_20 .&& (ipValid ==? 0))
                $ do
                  cond_
                    [ ipProto ==? ip_protocol_icmp ==> do
                        unpackFrom buf (safeCast ipOffset) decodedICMP

                        pingRep <- local $ izero
                        -- copy lastRx packet data and length
                        refCopy pingRep (lastRx ~> rx_packet_buffer)

                        rxLen <- (lastRx ~> rx_packet_buffer ~>* stringLengthL)
                        icmpValid <- checksum
                          pingRep
                          ipOffset -- from
                          (rxLen - safeCast ipOffset) -- length

                        comment "ICMP Checksum"
                        assert (icmpValid ==? 0x0)

                        ethHeader <- local
                            $ istruct [ eth_header_eth_type .= ival ether_type_ipv4 ]

                        refCopy
                          (ethHeader ~> eth_header_target_mac)
                          (decodedHeader ~> eth_header_source_mac)
                        refCopy
                          (ethHeader ~> eth_header_source_mac)
                          macAddr

                        packInto (pingRep ~> stringDataL) 0 (constRef ethHeader)

                        ipHeader <- local
                            $ istruct
                                [ ip_header_version_ihl .= ival ip_version_ihl_4_20
                                , ip_header_ident .= ival 0x1337
                                , ip_header_ttl .= ival 64
                                , ip_header_protocol .= ival ip_protocol_icmp
                                ]

                        refCopy
                          (ipHeader ~> ip_header_source_address)
                          ipAddr
                        refCopy
                          (ipHeader ~> ip_header_target_address)
                          (decodedIP ~> ip_header_source_address)
                        refCopy
                          (ipHeader ~> ip_header_total_length)
                          (decodedIP ~> ip_header_total_length)

                        packInto
                          (pingRep ~> stringDataL)
                          (safeCast ethOffset)
                          (constRef ipHeader)

                        i <- checksum
                          pingRep
                          ethOffset
                          (safeCast ipHeaderLength)

                        store
                          (pingRep ~> stringDataL ! (toIx $ ethOffset + 10))
                          $ bitCast (i `iShiftR` 8)

                        store
                          (pingRep ~> stringDataL ! (toIx $ ethOffset + 11))
                          $ bitCast i

                        store
                          (decodedICMP ~> icmp_packet_type)
                          icmp_echo_reply

                        store
                          (decodedICMP ~> icmp_packet_checksum)
                          0

                        packInto
                          (pingRep ~> stringDataL)
                          (safeCast ipOffset)
                          (constRef decodedICMP)

                        x <- checksum
                          pingRep
                          ipOffset
                          (rxLen - safeCast ipOffset)

                        store
                          (pingRep ~> stringDataL ! (toIx $ ipOffset + 2))
                          $ bitCast (x `iShiftR` 8)

                        store
                          (pingRep ~> stringDataL ! (toIx $ ipOffset + 3))
                          $ bitCast x

                        emit txE (constRef pingRep)

                    , ipProto ==? ip_protocol_udp ==> do
                        unpackFrom buf (safeCast ipOffset) decodedUDP

                        refCopy udpRep (lastRx ~> rx_packet_buffer)

                        udpLen <- decodedUDP ~>* udp_header_length
                        incomingCheckSum <- decodedUDP ~>* udp_header_checksum

                        udpValid <- local $ ival true
                        unless
                          (incomingCheckSum ==? 0)
                          $ do
                              pseudoHeader <-
                                local
                                $ istruct [ ip_pseudo_header_protocol .= ival ip_protocol_udp ]
                              refCopy
                                (pseudoHeader ~> ip_pseudo_header_source_address)
                                (decodedIP ~> ip_header_source_address)
                              refCopy
                                (pseudoHeader ~> ip_pseudo_header_target_address)
                                (decodedIP ~> ip_header_target_address)
                              refCopy
                                (pseudoHeader ~> ip_pseudo_header_length)
                                (decodedUDP ~> udp_header_length)

                              -- put pseudo header right before udp header
                              packInto
                                (udpRep ~> stringDataL)
                                (safeCast $ ipOffset - ipPseudoHeaderLength)
                                (constRef pseudoHeader)

                              computedChecksum <-
                                checksum
                                  udpRep
                                  (ipOffset - ipPseudoHeaderLength)
                                  (safeCast $ ipPseudoHeaderLength + udpLen)

                              store udpValid (computedChecksum ==? 0)
                              comment "UDP checksum"
                              assert (computedChecksum ==? 0)

                        isValid <- deref udpValid
                        cond_
                          [ iNot isValid ==> invalidUDPs += 1
                          , isValid ==> do
                              -- pass downstream
                              udpPacket <- local $ izero
                              refCopy
                                (udpPacket ~> udp_packet_port)
                                (decodedUDP ~> udp_header_target_port)

                              store
                                (udpPacket ~> udp_packet_data_length)
                                (udpLen - udpHeaderLength)

                              store
                                (udpPacket ~> udp_packet_data_offset)
                                udpOffset

                              refCopy
                                (udpPacket ~> udp_packet_buffer)
                                (lastRx ~> rx_packet_buffer)

                              emit udpE (constRef udpPacket)
                          ]
                    ]
          ]

  pure (snd udp)
