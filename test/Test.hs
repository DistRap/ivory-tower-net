{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Main where

import Ivory.Artifact
import Ivory.Language
import Ivory.Serialize
import Ivory.Tasty

import Ivory.BSP.STM32.Driver.ETH (ethModule)
import Ivory.Tower.Net.Types

simpleChecksumTest :: Def ('[] :-> Sint32)
simpleChecksumTest = proc "main" $ body $ do
  -- https://www.saminiir.com/lets-code-tcp-ip-stack-2-ipv4-icmpv4/#internet-checksum
  z <-
    local
    $ istruct
      [ stringDataL .=
          ( iarray
            $ map ival
                [ 0x45, 0x00, 0x00, 0x54, 0x41, 0xE0, 0x40, 0x00
                , 0x40, 0x01, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x04
                , 0x0A, 0x00, 0x00, 0x05
                ]
          )
      , stringLengthL .= ival 20
      ]

  y <- checksum
    z
    0
    20

  ret ((y ==? 0xE4C0) ? (0, 1))

oddChecksumTest :: Def ('[] :-> Sint32)
oddChecksumTest = proc "main" $ body $ do
  -- https://www.saminiir.com/lets-code-tcp-ip-stack-2-ipv4-icmpv4/#internet-checksum
  z <-
    local
    $ istruct
      [ stringDataL .=
          ( iarray
            $ map ival [ 0x13, 0x37, 0x01 ]
          )
      , stringLengthL .= ival 3
      ]

  y <- checksum
    z
    0
    3

  ret ((y ==? 0xEBC8) ? (0, 1))

udpEven :: Def ('[] :-> Sint32)
udpEven = proc "main" $ body $ do
  z <-
    local
    $ istruct
      [ stringDataL .=
          ( iarray
            $ map ival
                [ 0x32, 0x54, 0x11, 0x7E, 0x5E, 0x20, 0x00, 0x0E, 0xC6, 0x87
                , 0x72, 0x01, 0x08, 0x00, 0x45, 0x00, 0x00, 0x1E, 0x66, 0x2C
                , 0x40, 0x00,
                  0xC0, 0xA8, 0xC0, 0x01, 0xC0, 0xA8, 0xC0, 0x02
                , 0x00, 0x11, 0x00, 0x0A, 0xA0, 0x00, 0x02, 0x15, 0x00, 0x0A
                , 0xFB, 0x0D
                , 0x61, 0x61
                ]
          )
      , stringLengthL .= ival 0x3C
      ]

  y <- checksum
    z
    (ipOffset - ipPseudoHeaderLength)
    (safeCast $ ipPseudoHeaderLength + 10)

  ret (safeCast y)

udpOdd :: Def ('[] :-> Sint32)
udpOdd = proc "main" $ body $ do
  z <-
    local
    $ istruct
      [ stringDataL .=
          ( iarray
            $ map ival
              [ 0x32, 0x54, 0x11, 0x7E, 0x5E, 0x20, 0x00, 0x0E, 0xC6, 0x87
              , 0x72, 0x01, 0x08, 0x00, 0x45, 0x00, 0x00, 0x1D, 0x01, 0x65
              , 0x40, 0x00
              , 0xC0, 0xA8, 0xC0, 0x01, 0xC0, 0xA8, 0xC0, 0x02
              , 0x00, 0x11, 0x00, 0x09, 0xB2, 0x37, 0x02, 0x15, 0x00, 0x09
              , 0xE9, 0x39
              , 0x61
              ]
          )
      , stringLengthL .= ival 0x3C
      ]

  y <- checksum
    z
    (ipOffset - ipPseudoHeaderLength)
    (safeCast $ ipPseudoHeaderLength + 9)

  ret (safeCast y)

netDeps :: [Module]
netDeps = [ethModule, netModule, serializeModule]

netArtifacts :: [Located Artifact]
netArtifacts = serializeArtifacts

main :: IO ()
main = defaultMain
  $ ivoryTestGroup netDeps netArtifacts
  $ map (setDeps (depend netModule))
    [ mkSuccess "simple checskum" simpleChecksumTest
    , mkSuccess "odd checskum" oddChecksumTest
    , mkSuccess "udp pseudoheader even data" udpEven
    , mkSuccess "udp pseudoheader odd data" udpOdd
    ]
