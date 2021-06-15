
module TestOVN where

import System.Random
import           Protolude
import           Test.Tasty
import           Test.Tasty.QuickCheck
import           Test.Tasty.HUnit

import           Crypto.Random.Types (MonadRandom)
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.ECDSA    as ECDSA
import           Schnorr
import           Schnorr.Internal
import           Schnorr.Curve as Curve

curveName :: Curve25519
curveName = Curve.Curve25519

type Point = ECC.Point

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

randomVotes :: Int -> IO [Bool]
randomVotes n = replicateM n randomIO

partition :: [a] -> Int -> ([a],[a])
partition xs i = case splitAt (i-1) xs of (as, bs) -> (as, drop 1 bs)

-- utils ----------------------------------------------------------------------

type Compute = ([Integer], [ECDSA.PublicPoint], [ECDSA.PrivateNumber], [ECC.Point], [ECC.Point])
type Computed = (Integer, ECDSA.PublicPoint, ECDSA.PrivateNumber, ECC.Point, ECC.Point)
type ComputeList = [Computed]

compute :: [Integer] -> IO Compute
compute vs = do
  keys <- mapM (const $ generateKeys curveName) vs
  let pk = map(ECDSA.public_q . fst) keys
      sk = map (ECDSA.private_d . snd) keys
      rk = map ((\(a,b) -> sump a +| (negp . sump $ b)) . partition pk) [1..length vs]
      vk = map bmul vs
    in pure (vs, pk, sk, rk, vk)

listify :: Compute -> ComputeList
listify ([],[],[],[],[]) = []
listify (v:vs, p:pk, s:sk, r:rk, vv:vk) = (v,p,s,r,vv) : listify (vs,pk,sk,rk,vk)
-- compute keys ---------------------------------------------------------------

search :: ECC.Point -> Integer
search p = aux 0 ECC.PointO p
  where
    aux i c p = if c == p then i else aux (i+1) (c +| g curveName) p

tally :: Compute -> Integer
tally (vs, _, sk, rk, vk) = search (sump $ zipWith (\v (s,r) -> (s *| r) +| v) vk (zip sk rk))

sumVs :: Compute -> Integer
sumVs (vs, _, _, _, _) = sum vs

-- tally ----------------------------------------------------------------------

proveKey :: MonadRandom m => Compute -> m Bool
proveKey c = and <$> mapM aux (listify c)
  where
    aux :: MonadRandom m => Computed -> m Bool
    aux (v, p, s, r, vv) = verify curveName g p <$> prove curveName g (p, s)
    g = pointBaseMul curveName 1

-- proof private key ----------------------------------------------------------

testOVNSet :: TestName -> IO Compute -> TestTree
testOVNSet tn c = testGroup tn
  [ testCase "tally" $ c >>= (\x -> tally x @?= sumVs x)
  , testCase "prove key" $ c >>= proveKey >>= (@?= True)]

testOVN :: TestTree
testOVN = testGroup "OVN test"
  [ withResource (compute [1,0,0,1,1]) d $ testOVNSet "[1,0,0,1,1] votes"]
  --, withResource (randomVotes 5 >>= compute) d $ testOVNSet "random 5 votes"
  --, withResource (randomVotes 100 >>= compute) d $ testOVNSet "random 100 votes"]
  where
    d :: a -> IO ()
    d = const $ pure ()