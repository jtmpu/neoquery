{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE DeriveAnyClass    #-}

module Nmap where

import qualified Data.Text as T
import Data.List
import Data.Maybe
import Data.Aeson
import Data.Either
import GHC.Generics
import Text.Regex.TDFA

data NmapFormat = NmapXML | NmapGrepable deriving (Show, Eq)
data Port = Port { port :: T.Text, portStatus :: T.Text, portProtocol :: T.Text, portService :: T.Text, serviceVersion :: T.Text } deriving (Show, Generic)
data ScanInfo = ScanInfo { ip :: T.Text, hostName :: T.Text, hostStatus :: T.Text, ports :: [Port] } deriving (Show, Generic)

instance FromJSON Port
instance ToJSON Port
instance FromJSON ScanInfo
instance ToJSON ScanInfo

data NmapParsingErrors = NmapParseGeneralError String | 
    NmapParseGrepableError String | 
    NmapParseXmlError String | 
    NmapParseGrepableHostError String |
    NmapParseGrepablePortError String
    deriving (Show, Eq)

createGError :: String -> NmapParsingErrors
createGError x = NmapParseGrepableError ("[!] " ++ x)

createGHError :: String -> NmapParsingErrors
createGHError x = NmapParseGrepableHostError ("[!]" ++ x)

createGPError :: String -> NmapParsingErrors
createGPError x = NmapParseGrepablePortError ("[!]" ++ x)

parseNmapGuessFormat :: String -> [Either [NmapParsingErrors] ScanInfo]
parseNmapGuessFormat contents = parseNmap format contents
    where format = guessNmapFormat contents

parseNmap :: NmapFormat -> String -> [Either [NmapParsingErrors] ScanInfo]
parseNmap NmapGrepable contents = parseNmapGrepable contents
parseNmap _ _ = [Left [NmapParseGeneralError "Invalid format"]]

guessNmapFormat :: String -> NmapFormat
guessNmapFormat contents
    | isXml = NmapXML
    | isGrepable = NmapGrepable
    | otherwise = NmapGrepable
    where isXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"  `isPrefixOf` contents
          isGrepable =  "# Nmap" `isPrefixOf` contents

{-|
XML Nmap output parsing
|-}
parseNmapXml :: String -> Either [NmapParsingErrors] [ScanInfo]
parseNmapXml _ = Left []

{-|
Grepable NMAP ouput parsing
This is quite disgusting, but i hate the format.

The general contents
# Nmap 7.70 scan initiated Mon Feb 10 15:58:39 2020 as: nmap -Pn -vvv -sV --top-ports 100 -oA nmap_scanme scanme.nmap.org
# Ports scanned: TCP(100;7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 45.33.32.156 (scanme.nmap.org)	Status: Up
Host: 45.33.32.156 (scanme.nmap.org)	Ports: 22/open/tcp//ssh//OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)/, 80/open/tcp//http//Apache httpd 2.4.7 ((Ubuntu))/	Ignored State: filtered (98)
# Nmap done at Mon Feb 10 15:58:53 2020 -- 1 IP address (1 host up) scanned in 14.02 seconds
|-}

-- Intermediary formats, used to combine data to a complete ScanInfo 
data GrepableHostStatus = GrepableHostStatus { gshIp :: T.Text, gshHostname :: T.Text, gshStatus :: T.Text }
data GrepablePortInfo = GrepablePortInfo { gshPortIp :: T.Text, gshPort :: T.Text, gshPortStatus :: T.Text, gshProtocol :: T.Text, gshService :: T.Text, gshVersion :: T.Text  }

-- Removes commented lines
parseNmapGrepable :: String -> [Either [NmapParsingErrors] ScanInfo]
parseNmapGrepable contents = parseNmapGrepable' filteredLines
    where filteredLines = filter (not . T.isPrefixOf "# ") $ map T.pack $ lines contents

-- Accepts a list of lines. We will only extract host status and port entries
parseNmapGrepable' :: [T.Text] -> [Either [NmapParsingErrors] ScanInfo]
parseNmapGrepable' l = Left errors : combineGrepableStructures hosts ports
    where hostParseResult = parseHostInfoGrepable (filter isHostStatusLine l)
          portParseResult = parsePortInfoGrepable (filter isPortStatusLine l)
          errors = concat $ lefts hostParseResult ++ lefts portParseResult
          hosts = rights hostParseResult
          ports = rights portParseResult

hostStatusRegex :: String
hostStatusRegex = "Host: ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}) \\(([^\\)]*)\\).*Status: ([^ ]+)"

isHostStatusLine :: T.Text -> Bool
isHostStatusLine x = T.unpack x =~ hostStatusRegex :: Bool

hostPortRegex :: String
hostPortRegex = "Host: ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}) \\(([^\\)]*)\\).*Ports:"

isPortStatusLine :: T.Text -> Bool
isPortStatusLine x = T.unpack x =~ hostPortRegex :: Bool

-- The actual grepable parsing
parseHostInfoGrepable :: [T.Text] -> [Either [NmapParsingErrors] GrepableHostStatus]
parseHostInfoGrepable [] = []
parseHostInfoGrepable (x:xs)
    | length values == 3 =
        Right (GrepableHostStatus (values !! 0) (values !! 1) (values !! 2)) : parseHostInfoGrepable xs
    | otherwise = Left [createGHError ("Cannot successfully parse the line '" ++ T.unpack x ++ "'")] : parseHostInfoGrepable xs
    -- Drop the first element, as the first matching is the entire line. The second element is the IP, third hostname and fourth is the status
    where values = map T.pack $ tail $ concat (T.unpack x =~ hostStatusRegex :: [[String]])

-- Manual ugly splicing of the string. If the string is divided by tabs, the second element should 
-- contain a nested list of ports separated by commas and slashes, just look at this:
-- Host: 45.33.32.156 (scanme.nmap.org)	Ports: 22/open/tcp//ssh//OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)/, 80/open/tcp//http//Apache httpd 2.4.7 ((Ubuntu))/	Ignored State: filtered (98)
parsePortInfoGrepable :: [T.Text] -> [Either [NmapParsingErrors] GrepablePortInfo]
parsePortInfoGrepable [] = []
parsePortInfoGrepable (x:xs)
    | length values == 2 && length elements >= 2 =
        parsePortsGrepable (head values) (elements !! 1) ++ parsePortInfoGrepable xs
    | length values /= 2 = 
        Left [createGPError ("Failed to parse IP for port entry: '" ++ T.unpack x ++ "'")] : parsePortInfoGrepable xs
    | otherwise =
        Left [createGPError ("Failed to parse ports for port entry: '" ++ T.unpack x ++ "'")] : parsePortInfoGrepable xs
    where elements = T.splitOn "\t" x
          values = map T.pack $ tail $ concat (T.unpack x =~ hostPortRegex :: [[String]])

-- Splits the line into parseable port-info entries, which are separated by a comma
parsePortsGrepable :: T.Text -> T.Text -> [Either [NmapParsingErrors] GrepablePortInfo]
parsePortsGrepable ip x = parsePortsGrepable' ip values
    where values = filter (not . T.null) $ concatMap (T.splitOn "Ports: ") $ T.splitOn ", " x

-- Extracts the port info. According to their documentation, the amount of slashes can vary so...
parsePortsGrepable' :: T.Text -> [T.Text] -> [Either [NmapParsingErrors] GrepablePortInfo]
parsePortsGrepable' ip [] = []
parsePortsGrepable' ip (x:xs)
    | length v >= 7 =
        Right (GrepablePortInfo ip (v !! 0) (v !! 1) (v !! 2) (v !! 4) (v !! 6)) : parsePortsGrepable' ip xs
    | length v >= 5 = 
        Right (GrepablePortInfo ip (v !! 0) (v !! 1) (v !! 2) (v !! 4) "") : parsePortsGrepable' ip xs
    | length v >= 3 =
        Right (GrepablePortInfo ip (v !! 0) (v !! 1) (v !! 2) "" "") : parsePortsGrepable' ip xs
    | otherwise = 
        Left [createGPError ("For ip '" ++ T.unpack ip ++ "', failed to properly split the ports entry '" ++ T.unpack x ++ "'.")] : parsePortsGrepable' ip xs
    where v = T.splitOn "/" x


-- To avoid some adhoc assumption that a port entry occurs after a host status entry, or that both of them exists if one does, 
-- we attempt to combine the information retrieved.! [Either [NmapParsingErrors] ScanInfo]
-- IP will be the unique ID for results
combineGrepableStructures :: [GrepableHostStatus] -> [GrepablePortInfo] -> [Either [NmapParsingErrors] ScanInfo]
combineGrepableStructures hosts ports = combineGrepableStructures' ips hosts ports
    where ips = nub $ map gshIp hosts ++ map gshPortIp ports

-- For each IP, create a ScanInfo record
combineGrepableStructures' :: [T.Text] -> [GrepableHostStatus] -> [GrepablePortInfo] -> [Either [NmapParsingErrors] ScanInfo]
combineGrepableStructures' [] _ _ = []
combineGrepableStructures' (x:xs) hosts ports
    -- Extract info and create
    | length hostElems == 1 || length portElems > 1 =
        Right (extractGrepableInfo x (Just (head hostElems)) portElems) : combineGrepableStructures' xs hosts ports
    | null hostElems && length portElems > 1 =
        Right (extractGrepableInfo x Nothing portElems) : combineGrepableStructures' xs hosts ports
    -- Something weird has happened, propagate errors
    | null hostElems && null portElems =
        Left [createGError ("Could not find either host or port entries for IP: " ++ T.unpack x)] : combineGrepableStructures' xs hosts ports
    | length hostElems > 1 && null portElems =
        Left [createGError ("Found multiple host entries for IP: " ++ T.unpack x)] : combineGrepableStructures' xs hosts ports
    | otherwise =
        Left [createGError ("Unknown errror for parsed IP: " ++ T.unpack x)] : combineGrepableStructures' xs hosts ports
    where hostElems = filter (\y -> gshIp y == x) hosts
          portElems = filter (\y -> gshPortIp y == x) ports

extractGrepableInfo :: T.Text -> Maybe GrepableHostStatus -> [GrepablePortInfo] -> ScanInfo
extractGrepableInfo ip (Just host) ports = ScanInfo ip (gshHostname host) (gshStatus host) (convertGrepablePorts ports)
extractGrepableInfo ip Nothing ports = ScanInfo ip "" "" (convertGrepablePorts ports)

--gshPortIp :: T.Text, gshPort :: T.Text, gshPortStatus :: T.Text, gshProtocol :: T.Text, gshService :: T.Text, gshVersion ::
convertGrepablePorts :: [GrepablePortInfo] -> [Port]
convertGrepablePorts = map (\ x-> Port (gshPort x) (gshPortStatus x) (gshProtocol x) (gshService x) (gshVersion x))