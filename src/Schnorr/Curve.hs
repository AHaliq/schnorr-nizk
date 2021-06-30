module Schnorr.Curve where

import qualified Crypto.PubKey.ECC.Generate   as ECC
import qualified Crypto.PubKey.ECC.Prim       as ECC
import qualified Crypto.PubKey.ECC.Types      as ECC
import qualified Crypto.PubKey.ECC.ECDSA      as ECDSA
import           Crypto.Random.Types          (MonadRandom)
import           Protolude

import qualified Schnorr.Curve25519 as Curve25519

data Curve25519 = Curve25519 deriving Show
data CurveAltBn128G1 = CurveAltBn128G1 deriving Show
newtype SECCurve = SECCurve { unSEC :: ECC.CurveName } deriving Show

class (Show a) => Curve a where
  curve :: a -> ECC.Curve
  cc :: a -> ECC.CurveCommon
  a :: a -> Integer
  n :: a -> Integer
  g :: a -> ECC.Point
  h :: a -> Integer
  isPointValid :: a -> ECC.Point -> Bool
  pointMul :: a -> Integer -> ECC.Point -> ECC.Point
  pointAdd :: a -> ECC.Point -> ECC.Point -> ECC.Point
  pointNegate :: a -> ECC.Point -> ECC.Point
  pointDouble :: a -> ECC.Point -> ECC.Point
  generateKeys :: MonadRandom m => a -> m (ECDSA.PublicKey, ECDSA.PrivateKey)
  isPointAtInfinity :: a -> ECC.Point -> Bool
  pointAddTwoMuls :: a -> Integer -> ECC.Point -> Integer -> ECC.Point -> ECC.Point
  pointBaseMul :: a -> Integer -> ECC.Point

instance Curve SECCurve where
  curve = ECC.getCurveByName . unSEC
  cc = ECC.common_curve . curve
  a = ECC.ecc_a . cc
  n = ECC.ecc_n . cc
  g = ECC.ecc_g . cc
  h = ECC.ecc_h . cc
  isPointValid = ECC.isPointValid . curve
  pointMul = ECC.pointMul . curve
  pointAdd = ECC.pointAdd . curve
  pointNegate = ECC.pointNegate . curve
  pointDouble = ECC.pointDouble . curve
  generateKeys = ECC.generate . curve
  isPointAtInfinity = const ECC.isPointAtInfinity
  pointAddTwoMuls = ECC.pointAddTwoMuls . curve
  pointBaseMul = ECC.pointBaseMul . curve

instance Curve Curve25519 where
  curve = const Curve25519.curve25519
  cc = ECC.common_curve . curve
  a = ECC.ecc_a . cc
  n = ECC.ecc_n . cc
  g = ECC.ecc_g . cc
  h = ECC.ecc_h . cc
  isPointValid = Curve25519.isPointValid . curve
  pointMul = Curve25519.pointMul . curve
  pointAdd = Curve25519.pointAdd . curve
  pointNegate = Curve25519.pointNegate . curve
  pointDouble = Curve25519.pointDouble . curve
  generateKeys = Curve25519.generateKeys . curve
  isPointAtInfinity = const ECC.isPointAtInfinity
  pointAddTwoMuls = Curve25519.pointAddTwoMuls . curve
  pointBaseMul = Curve25519.pointBaseMul . curve

curveAltBn128G1 :: ECC.Curve
curveAltBn128G1 =
  ECC.CurveFP $
    ECC.CurvePrime
      0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47
      ECC.CurveCommon
        { ecc_a = 0x0,
          ecc_b = 0x3,
          ecc_g = ECC.Point 0x1 0x2,
          ecc_n = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001,
          ecc_h = 0x1
        }
{-
ecc_a = 0
ecc_b = 3
ecc_g = (1,2)
ecc_n = 21888242871839275222246405745257275088548364400416034343698204186575808495617
ecc_h = 1
-}

instance Curve CurveAltBn128G1 where
  curve = const curveAltBn128G1
  cc = ECC.common_curve . curve
  a = ECC.ecc_a . cc
  n = ECC.ecc_n . cc
  g = ECC.ecc_g . cc
  h = ECC.ecc_h . cc
  isPointValid = ECC.isPointValid . curve
  pointMul = ECC.pointMul . curve
  pointAdd = ECC.pointAdd . curve
  pointNegate = ECC.pointNegate . curve
  pointDouble = ECC.pointDouble . curve
  generateKeys = ECC.generate . curve
  isPointAtInfinity = const ECC.isPointAtInfinity
  pointAddTwoMuls = ECC.pointAddTwoMuls . curve
  pointBaseMul = ECC.pointBaseMul . curve