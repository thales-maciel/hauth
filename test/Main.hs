module Main (main) where

import Hauth.API (hauthAPI)
import System.Exit (exitSuccess)

main :: IO ()
main =
    hauthAPI `seq` exitSuccess
