module Main (main) where

import Hauth.API (hauthAPI)
import Hauth.Server (app)
import System.Exit (exitSuccess)

main :: IO ()
main =
    hauthAPI `seq` app `seq` exitSuccess
