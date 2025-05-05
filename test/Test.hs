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

samplesTest :: Def ('[] :-> Sint32)
samplesTest = proc "main" $ body $ do
  -- https://www.saminiir.com/lets-code-tcp-ip-stack-2-ipv4-icmpv4/#internet-checksum
  z <-
    local
    $ istruct
      [ stringDataL .=
          ( iarray
            $ map ival
                [ 0x45, 0x00, 0x00, 0x54, 0x41, 0xe0, 0x40, 0x00,
                  0x40, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x04,
                  0x0a, 0x00, 0x00, 0x05
                ]
          )
      , stringLengthL .= ival 20
      ]

  y <- checksum
    z
    0
    20

  ret ((y ==? 0xe4c0) ? (0, 1))

netDeps :: [Module]
netDeps = [ethModule, netModule, serializeModule]

netArtifacts :: [Located Artifact]
netArtifacts = serializeArtifacts

main :: IO ()
main = defaultMain
  $ ivoryTestGroup netDeps netArtifacts
  $ map (setDeps (depend netModule))
    [ mkSuccess "simple checskum" samplesTest ]
