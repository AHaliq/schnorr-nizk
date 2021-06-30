{-# LANGUAGE TemplateHaskell #-}
module TestOVN where

import           System.Random
import           Control.Lens
import           Control.Arrow
import           Data.ByteString.Conversion
import           Data.ByteString (unpack)
import           Protolude
import           Test.Tasty
import           Test.Tasty.QuickCheck
import           Test.Tasty.HUnit
import           Crypto.Hash.SHA256
import           Crypto.Random.Types (MonadRandom)
import qualified Crypto.PubKey.ECC.Prim     as ECC
import qualified Crypto.PubKey.ECC.Types    as ECC
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.ECDSA    as ECDSA
import           Schnorr
import           Schnorr.Internal
import           Schnorr.Curve as Curve
import           Schnorr.Curve25519 (curve25519)

curveName :: CurveAltBn128G1
curveName = Curve.CurveAltBn128G1

q :: Integer
q = case Curve.curveAltBn128G1 of (ECC.CurveFP (ECC.CurvePrime _ ECC.CurveCommon {..})) -> ecc_n

type Point = ECC.Point

-- aliases --------------------------------------------------------------------

(+%) :: Integer -> Integer -> Integer
(+%) a b = (a + b) `mod` q

(-%) :: Integer -> Integer -> Integer
(-%) a b = let aN = if a > b then a else a + q in (aN - b) `mod` q

(*%) :: Integer -> Integer -> Integer
(*%) a b = (a * b) `mod` q

-- modular arithmetic ops -----------------------------------------------------

(+|) :: Point -> Point -> Point
(+|) = pointAdd curveName

(*|) :: Integer -> Point -> Point
(*|) = pointMul curveName

bmul :: Integer -> Point
bmul = pointBaseMul curveName

negp :: Point -> Point
negp = pointNegate curveName

sump :: [ECC.Point] -> ECC.Point
sump = foldl (+|) ECC.PointO

-- group ops ------------------------------------------------------------------

randomVotes :: Int -> IO [Bool]
randomVotes n = replicateM n randomIO

partition :: [a] -> Int -> ([a],[a])
partition xs i = case splitAt (i-1) xs of (as, bs) -> (as, drop 1 bs)

-- utils ----------------------------------------------------------------------

data CDSProofVars
  = CDSProofVars
    { a1 :: Point
    , b1 :: Point
    , a2 :: Point
    , b2 :: Point
    } deriving (Show, Eq)

data CDSProofParam
  = CDSProofParam
    { d1 :: Integer
    , d2 :: Integer
    , r1 :: Integer
    , r2 :: Integer
    } deriving (Show, Eq)
data CDSProof
  = CDSProof
    { vars :: CDSProofVars
    , params :: CDSProofParam
    } deriving (Show, Eq)
data Voter''
  = Voter''
    { _i :: Int
    , _x :: Integer
    , _xG :: Point
    , _b :: Bool
    } deriving (Show, Eq)
makeLenses ''Voter''
data Voter'
  = Voter'
    { _v'' :: Voter''
    , _yG :: Point
    , _y' :: Point
    } deriving (Show, Eq)
makeLenses ''Voter'

data Voter
  = Voter
    { _v' :: Voter'
    , _xProof :: NIZKProof
    , _yProof :: CDSProof
    } deriving (Show, Eq)
makeLenses ''Voter

-- voter data -----------------------------------------------------------------

getHash :: Voter' -> CDSProofVars -> Integer
getHash Voter'{_v''=Voter''{..},..} CDSProofVars{..} =
  oracle curveName $ toByteString' _x <> foldl (<>) mempty (map appendCoordinates [_xG, _y', a1, b1, a2, b2])

getHashProof :: Voter' -> CDSProof -> Integer
getHashProof v CDSProof{..} = getHash v vars

proveCDS :: MonadRandom m => Bool -> Voter' -> m CDSProof
proveCDS yes v'@Voter'{_v''=Voter''{..},..} =
  do
  (wG, w) <- genCommitment curveName (g curveName)
  (dG, d) <- genCommitment curveName (g curveName)
  (rG, r) <- genCommitment curveName (g curveName)
  let
    vars = CDSProofVars
      { a1 = if yes then rG +| (_x *| dG) else wG
      , b1 = if yes then (r *| _yG) +| (d *| ((_x *| _yG) +| g curveName)) else w *| _yG
      , a2 = if yes then wG else rG +| (_x *| dG)
      , b2 = if yes then w *| _yG else (d *| (_x *| _yG)) +| (r *| _yG) +| (d *| negp (g curveName))
      }
    c = getHash v' vars
    d' = c -% d
    r' = w -% (_x *% d')
    in
    pure $ CDSProof
      { vars = vars
      , params = CDSProofParam
        { d1 = if yes then d else d'
        , d2 = if yes then d' else d
        , r1 = if yes then r else r'
        , r2 = if yes then r' else r
        }
      }

verifyPoint :: Point -> Bool
verifyPoint = isPointValid curveName

verifyVoter :: Voter' -> Bool
verifyVoter Voter'{_v''=Voter''{..},..} = all verifyPoint [_xG, _yG, _y']

verifyYProof :: CDSProof -> Bool
verifyYProof CDSProof{vars=CDSProofVars{..},..} = all verifyPoint [a1, b1, a2, b2]

verifyCDS :: Voter -> Bool
verifyCDS Voter
  { _v'=_v'@Voter'{_v''=Voter''{..},..}
  , _yProof=yP@CDSProof
    { vars=CDSProofVars{..}
    , params=CDSProofParam{..}
    }
  , ..} =
  and [verifyKeys, verifyC, verifyA1, verifyB1, verifyA2, verifyB2]
  where
    verifyKeys = verifyVoter _v' && verifyYProof yP
    verifyC = getHashProof _v' yP == d1 +% d2
    verifyA1 = a1 == (d1 *| _xG) +| (r1 *| g curveName)
    verifyB1 = b1 == (r1 *| _yG) +| (d1 *| _y')
    verifyA2 = a2 == (r2 *| g curveName) +| (d2 *| _xG)
    verifyB2 = b2 == (r2 *| _yG) +| (d2 *| (negp (g curveName) +| _y'))

verifyNIZK :: Voter -> Bool
verifyNIZK Voter{_v'=Voter'{_v''=Voter''{..}},..} = verify curveName (g curveName) _xG _xProof

-- prove verify ---------------------------------------------------------------

compute'' :: Int -> Bool -> IO Voter''
compute'' i b = do
  (xG, x) <- (ECDSA.public_q *** ECDSA.private_d) <$> generateKeys curveName
  pure Voter''
    { _i = i
    , _x = x
    , _xG = xG
    , _b = b
    }

compute' :: [Voter''] -> [Voter']
compute' vs = zipWith aux vs $ map (partition (map (^. xG) vs) . (^. i)) vs
  where
    aux v''@Voter''{..} (lhs,rhs) =
      let
        yG = sump lhs +| (negp . sump $ rhs)
      in
      Voter'
        { _v'' = v''
        , _yG = yG
        , _y' = let y' = _x *| yG in if _b then y' +| g curveName else y'
        }

compute :: MonadRandom m => Voter' -> m Voter
compute v'@Voter'{_v''=Voter''{..},..} = do
  xP <- prove curveName (g curveName) (_xG, _x)
  yP <- proveCDS _b v'
  pure $ Voter
    { _v' = v'
    , _xProof = xP
    , _yProof = yP
    }

computeList :: [Bool] -> IO [Voter]
computeList bs = zipWithM compute'' [1..length bs] bs <&> compute' >>= mapM compute

-- compute keys ---------------------------------------------------------------

search :: Point -> Integer
search p = aux 0 ECC.PointO p
  where
    aux i c p = if c == p then i else aux (i+1) (c +| g curveName) p

tally :: [Voter] -> Integer
tally vs = search $ aux vs
  where
    aux [] = ECC.PointO
    aux (Voter{_v'=Voter'{..}}:vs) =_y' +| aux vs

sumVs :: [Voter] -> Integer
sumVs vs = sum $ map ((\x -> if x then 1 else 0) . (^. b) . (^. v'') . (^. v')) vs

-- tally ----------------------------------------------------------------------

testOVNSet :: TestName -> IO [Voter] -> TestTree
testOVNSet tn c = testGroup tn
  [ testCase "tally" $ c >>= (\x -> tally x @?= sumVs x)
  , testCase "CDSProof" $ c <&> all verifyCDS >>= (@?= True)
  , testCase "NIZKProof" $ c <&> all verifyNIZK >>= (@?= True)]

testOVN :: TestTree
testOVN = testGroup "OVN test"
  [ withResource (computeList [True,False, False, True, True]) d $ testOVNSet "[1,0,0,1,1] votes"
  , withResource (randomVotes 5 >>= computeList) d $ testOVNSet "random 5 votes"
  , withResource (randomVotes 100 >>= computeList) d $ testOVNSet "random 100 votes"]
  where
    d :: a -> IO ()
    d = const $ pure ()