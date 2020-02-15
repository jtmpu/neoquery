module Lib
    ( someFunc
    ) where

import qualified Data.ByteString.Lazy as BSL
import Options.Applicative
import Data.Semigroup ((<>))
import System.Directory
import Data.Aeson
import Data.Either

import qualified Nmap as N

data NeoqueryArgs = NeoqueryArgs
    {
        filepath :: String,
        print ::  Bool,
        quiet :: Bool
    }

neoqueryArgs :: Parser NeoqueryArgs
neoqueryArgs = NeoqueryArgs
    <$> strOption ( long "filepath"
        <> short 'f'
        <> metavar "NMAP file"
        <> help "The filepath of the nmap scan results. (Can be both XML and the grepable)" )
    <*> switch ( long "print" <> short 'p' <> help "Write JSON to STDOUT")
    <*> switch ( long "quiet" <> short 'q' <> help "Dont ouput error messages to STDERR")

someFunc :: IO ()
someFunc = run =<< execParser opts
    where
        opts = info (neoqueryArgs <**> helper)
            (fullDesc
            <> progDesc "Import NMAP scan results to neo4j"
            <> header "NeoQuery")

run :: NeoqueryArgs -> IO ()
run (NeoqueryArgs f True quiet) = do
    exists <- doesFileExist f
    if exists then do
        contents <- readFile f
        let parsedHosts = N.parseNmapGuessFormat contents
        printHosts quiet parsedHosts
    else putStrLn $ "File not found: " ++ f
run _ = return ()

printHosts :: Bool -> [Either [N.NmapParsingErrors] N.ScanInfo] -> IO ()
printHosts _ [] = return ()
printHosts False v = do
    let errs = concat $ lefts v
    mapM_ (putStrLn . show) errs
    let d = map encode $ rights v
    mapM_ BSL.putStrLn d
printHosts True v = do
    let d = map encode $ rights v
    mapM_ BSL.putStrLn d