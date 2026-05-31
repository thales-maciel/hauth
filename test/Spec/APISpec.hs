module Spec.APISpec (runSpec) where

import Hauth.API (hauthAPI)
import Hauth.Server (server)

runSpec :: IO ()
runSpec = do
    hauthAPI `seq` server `seq` pure ()
