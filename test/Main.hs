{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Protolude
import           Test.Tasty
import           Test.Tasty.HUnit

import TestSchnorr
import TestGroupLaws
import TestCurveOps
import TestOVN

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests"
  [ testOVN--testGroupLaws
  --, testCurveOps
  --, testSchnorr
  ]
