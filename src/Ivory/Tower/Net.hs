{-# LANGUAGE DataKinds #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeOperators #-}

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

import qualified Ivory.Base

netTower
  :: NetConfig
  -> ( ChanOutput ('Stored IBool)
     , BackpressureTransmit FrameBuffer ('Stored IBool)
     , ChanOutput (Struct "rx_packet")
     )
  -> Tower
       e
       ( BackpressureTransmit (Struct "udp_tx") (Stored IBool)
       , ChanOutput (Struct "udp_rx")
       )
netTower NetConfig{..} (ready, BackpressureTransmit txReq _txDone, rxDone) = do
  netTowerDeps

  arpResolve <- channel
  udpRx <- channel
  udpTx <- channel
  udpTxDone <- channel
  udpTxResolved <- channel

  monitor (named mempty) $ do
    ethReady <- state (named "EthReady")
    txCounter <-
      stateInit
        (named "TxCounter")
        (ival (0 :: Uint8))

    lastRx <- state (named "LastRx")
    rxCounter <-
      stateInit
        (named "RxCounter")
        (ival (0 :: Uint8))

    pendingTx <- state (named "PendingTx")

    (macAddr :: Ref Global (Array 6 (Stored Uint8))) <-
      stateInit
        (named "MacAddr")
        (iarray $ map ival $ unMACAddress netConfigMACAddress)

    (ipAddr :: Ref Global (Array 4 (Stored Uint8))) <-
      stateInit
        (named "IpAddr")
        (iarray $ map ival $ unIPAddress netConfigIPAddress)

    (decodedHeader :: Ref Global (Struct "eth_header")) <-
      state (named "DecodedHeader")
    (decodedARP :: Ref Global (Struct "arp_packet")) <-
      state (named "DecodedARP")
    (decodedIP :: Ref Global (Struct "ip_header")) <-
      state (named "DecodedIP")
    (decodedICMP :: Ref Global (Struct "icmp_packet")) <-
      state (named "DecodedICMP")
    (decodedUDP :: Ref Global (Struct "udp_header")) <-
      state (named "DecodedUDP")

    (arpTable :: Ref Global (Array 10 (Struct "arp_entry"))) <-
      state (named "ArpTable")

    let arpLookup
          :: ( GetAlloc eff ~ 'Scope s
             , GetAlloc (AllowBreak eff) ~ 'Scope s
             , GetBreaks (AllowBreak eff) ~ 'Break
             )
          => ConstRef s1 (Array 4 (Stored Uint8))
          -> (Ref Global (Array 6 (Stored Uint8)) -> Ivory (AllowBreak eff) ())
          -> Ivory eff IBool
        arpLookup protoAddr withFound = do
          found <- local izero
          arrayMap $ \ix -> do
            valid <- (arpTable ! ix) ~>* arp_entry_valid
            when valid $ do
              protoEq <- arrayEq
                ((arpTable ! ix) ~> arp_entry_proto_addr)
                protoAddr
              when
                protoEq
                $ do
                    store found true
                    withFound ((arpTable ! ix) ~> arp_entry_hw_addr)
                    breakOut
          deref found >>= pure

    arpTableFull <- state (named "ArpTableFull")
    invalidIPs <- stateInit (named "InvalidIPs") (ival (0 :: Uint32))
    invalidUDPs <- stateInit (named "InvalidUDPs") (ival (0 :: Uint32))

    -- use states instead of allocating on stack
    arpReq <- state (named "ArpReq")
    arpRep <- state (named "ArpRep")
    udpReq <- state (named "UdpReq")
    udpRep <- state (named "UdpRep")

    handler ready (named "EthReady") $ do
      callback $ const $ store ethReady true

    handler (snd arpResolve) (named "ArpResolve") $ do
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

    handler (snd udpTx) (named "UdpTx") $ do
      arpResolveE <- emitter (fst arpResolve) 1
      udpTxResolvedE <- emitter (fst udpTxResolved) 1
      callback $ \tx -> do
        refCopy
          pendingTx
          tx

        found <-
          arpLookup
            (tx ~> udp_tx_ip)
            (emit udpTxResolvedE . constRef)

        unless
          found
          $ emit arpResolveE (tx ~> udp_tx_ip)

    handler (snd udpTxResolved) (named "UdpTxResolved") $ do
      txE <- emitter txReq 1
      udpTxDoneE <- emitter (fst udpTxDone) 1
      callback $ \targetMac -> do
        txCounter += 1

        udpDataLength <-
              (bitCast :: Uint32 -> Uint16) . signCast
          <$> (pendingTx ~> udp_tx_data ~>* stringLengthL)

        udpPort <- pendingTx ~>* udp_tx_port

        ethHeader <- local
            $ istruct [ eth_header_eth_type .= ival ether_type_ipv4 ]

        refCopy
          (ethHeader ~> eth_header_target_mac)
          targetMac
        refCopy
          (ethHeader ~> eth_header_source_mac)
          macAddr

        packInto (udpReq ~> stringDataL) 0 (constRef ethHeader)

        ipHeader <- local
            $ istruct
                [ ip_header_version_ihl .= ival ip_version_ihl_4_20
                , ip_header_ident .= ival 0x1337
                , ip_header_ttl .= ival 64
                , ip_header_protocol .= ival ip_protocol_udp
                ]

        refCopy
          (ipHeader ~> ip_header_source_address)
          ipAddr
        refCopy
          (ipHeader ~> ip_header_target_address)
          (pendingTx ~> udp_tx_ip)

        store
          (ipHeader ~> ip_header_total_length)
          (   ipHeaderLength
            + udpHeaderLength
            + udpDataLength
          )

        packInto
          (udpReq ~> stringDataL)
          (safeCast ethOffset)
          (constRef ipHeader)

        ipChecksum <- checksum
          udpReq
          ethOffset
          (safeCast ipHeaderLength)

        storeChecksum
          udpReq
          ipChecksumOffset
          ipChecksum

        pseudoHeader <-
          local
            $ istruct [ ip_pseudo_header_protocol .= ival ip_protocol_udp ]
        refCopy
          (pseudoHeader ~> ip_pseudo_header_source_address)
          ipAddr
        refCopy
          (pseudoHeader ~> ip_pseudo_header_target_address)
          (pendingTx ~> udp_tx_ip)
        store
          (pseudoHeader ~> ip_pseudo_header_length)
          (   udpHeaderLength
            + udpDataLength
          )

        -- put pseudo header right after IP header
        packInto
          (udpReq ~> stringDataL)
          (safeCast ipOffset)
          (constRef pseudoHeader)

        pseudoHeaderChecksum <-
          checksum
            udpReq
            ipOffset
            (safeCast ipPseudoHeaderLength)

        udpHeader <-
          local
            $ istruct
                [ udp_header_source_port .= ival udpPort
                , udp_header_target_port .= ival udpPort
                , udp_header_length      .= ival (udpDataLength + udpHeaderLength)
                ]

        packInto
          (udpReq ~> stringDataL)
          (safeCast ipOffset)
          (constRef udpHeader)

        arrayCopy
          (udpReq ~> stringDataL)
          (pendingTx ~> udp_tx_data ~> stringDataL)
          (safeCast udpOffset)
          (safeCast udpDataLength)

        udpChecksum <-
          checksum
            udpReq
            ipOffset
            (safeCast $ udpDataLength + udpHeaderLength)

        combined
          <- assign
          $ bitCast
          $ iComplement
          $ (\x -> (x >=? 0xFFFF) ? (x + 1, x))
          $   ((safeCast :: Uint16 -> Uint32) $ iComplement pseudoHeaderChecksum)
            + ((safeCast :: Uint16 -> Uint32) $ iComplement udpChecksum)

        storeChecksum
          udpReq
          udpChecksumOffset
          combined

        store
          (udpReq ~> stringLengthL)
          (safeCast $ ethHeaderLength + ipHeaderLength + udpHeaderLength + udpDataLength)

        emit txE (constRef udpReq)
        -- this should be hooked to ethernet drivers _txDone
        -- but since it is a ring of at least two descriptors, it's fine for now
        emitV udpTxDoneE true

    handler rxDone (named "Rx") $ do
      udpE <- emitter (fst udpRx) 1
      udpTxResolvedE <- emitter (fst udpTxResolved) 1
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
                    emit
                      udpTxResolvedE
                      $ constRef (decodedARP ~> arp_sender_hw_addr)

                    merged <-
                      arpLookup
                        (constRef (decodedARP ~> arp_sender_proto_addr))
                        (\mac ->
                            refCopy
                              mac
                              (decodedARP ~> arp_sender_hw_addr)
                        )

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
              unless
                (ipValid ==? 0)
                (invalidIPs += 1)

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

                        ipChecksum <- checksum
                          pingRep
                          ethOffset
                          (safeCast ipHeaderLength)

                        storeChecksum
                          pingRep
                          ipChecksumOffset
                          ipChecksum

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

                        icmpChecksum <- checksum
                          pingRep
                          ipOffset
                          (rxLen - safeCast ipOffset)

                        storeChecksum
                          pingRep
                          icmpChecksumOffset
                          icmpChecksum

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

                        isValid <- deref udpValid
                        cond_
                          [ iNot isValid ==> invalidUDPs += 1
                          , isValid ==> do
                              -- pass downstream
                              udpRxMsg <- local $ izero
                              refCopy
                                (udpRxMsg ~> udp_rx_port)
                                (decodedUDP ~> udp_header_target_port)

                              Ivory.Base.arrayCopyFromOffset
                                (udpRxMsg ~> udp_rx_data ~> stringDataL)
                                (lastRx ~> rx_packet_buffer ~> stringDataL)
                                (safeCast udpOffset)
                                (safeCast $ udpLen - udpHeaderLength)

                              store
                                (udpRxMsg ~> udp_rx_data ~> stringLengthL)
                                (safeCast $ udpLen - udpHeaderLength)

                              emit udpE (constRef udpRxMsg)
                          ]
                    ]
          ]

  pure
    ( BackpressureTransmit (fst udpTx) (snd udpTxDone)
    , snd udpRx
    )
  where
    named :: String -> String
    named = ("net"++)

storeChecksum
  :: Ref s FrameBuffer
  -> Uint16
  -> Uint16
  -> Ivory eff ()
storeChecksum buffer offset csum = do
  store
    (buffer ~> stringDataL ! (toIx offset))
    $ bitCast (csum `iShiftR` 8)

  store
    (buffer ~> stringDataL ! (toIx $ offset + 1))
    $ bitCast csum
