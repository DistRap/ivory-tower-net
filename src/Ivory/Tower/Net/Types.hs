{-# LANGUAGE RecordWildCards #-}

module Ivory.Tower.Net.Types
  ( IPAddress(..)
  , mkIPAddress
  , MACAddress(..)
  , mkMACAddress
  , NetConfig(..)
  , defaultNetConfig
  , netConfigParser
  , module Ivory.BSP.STM32.Driver.ETH.RxPacket
  , module Ivory.Tower.Net.Checksum
  , module Ivory.Tower.Net.Structs
  , module Ivory.Tower.Net.Types.ARP
  , module Ivory.Tower.Net.Types.EtherType
  , module Ivory.Tower.Net.Types.ICMP
  , module Ivory.Tower.Net.Types.IP
  , module Ivory.Tower.Net.Types.TCP
  , module Ivory.Tower.Net.Util
  ) where

import Ivory.Language
import Ivory.Tower.Config
import Ivory.BSP.STM32.Driver.ETH.RxPacket

import Ivory.Tower.Net.Checksum
import Ivory.Tower.Net.Structs
import Ivory.Tower.Net.Types.ARP
import Ivory.Tower.Net.Types.EtherType
import Ivory.Tower.Net.Types.ICMP
import Ivory.Tower.Net.Types.IP
import Ivory.Tower.Net.Types.TCP
import Ivory.Tower.Net.Util

newtype IPAddress = IPAddress { unIPAddress :: [Uint8] }
  deriving Show

mkIPAddress :: String -> IPAddress
mkIPAddress = IPAddress . ipToList

newtype MACAddress = MACAddress { unMACAddress :: [Uint8] }
  deriving Show

mkMACAddress :: String -> MACAddress
mkMACAddress = MACAddress . macToList

data NetConfig = NetConfig
  { netConfigIPAddress  :: IPAddress
  , netConfigMACAddress :: MACAddress
  } deriving Show

defaultNetConfig :: NetConfig
defaultNetConfig = NetConfig
  { netConfigIPAddress  = mkIPAddress "192.168.192.2"
  , netConfigMACAddress = mkMACAddress "32:54:11:7e:5e:20"
  }

netConfigParser :: ConfigParser NetConfig
netConfigParser = subsection "ip" $ do
  netConfigIPAddress <- mkIPAddress <$> subsection "ip-address" string
  netConfigMACAddress <- mkMACAddress <$> subsection "mac-address" string
  pure NetConfig{..}
