module Main (main) where

import Hauth.Server (runServer)
import System.Environment (lookupEnv)
import System.Exit (die)
import Text.Read (readMaybe)

main :: IO ()
main = do
    port <- resolvePort
    runServer port

resolvePort :: IO Int
resolvePort =
    lookupEnv "HAUTH_PORT" >>= \case
        Nothing ->
            pure 8080
        Just value ->
            maybe
                (die ("Invalid HAUTH_PORT: " <> value))
                pure
                (readMaybe value)
