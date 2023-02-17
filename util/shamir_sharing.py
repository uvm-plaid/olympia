import numpy as np
import galois
from nacl.public import PrivateKey, Box
from io import BytesIO

import cProfile
import re

# A library for Shamir sharing arrays of field elements
# - An ArrayShare object is one share of the whole array
#   - ArrayShare objects have encrypt and decrypt methods
# - share_array secret shares an array, returning a dict mapping x coordinates
#   to their corresponding ArrayShare objects
# - reconstruct_array reconstructs the original array, given a list of
#   ArrayShare objects
# - sum_share_array performs a column-wise sum of a list of ArrayShare objects
#   that all agree on the x coordinate

# convert a numpy array to bytes
def array_to_bytes(x: np.ndarray) -> bytes:
    np_bytes = BytesIO()
    np.save(np_bytes, x, allow_pickle=True)
    return np_bytes.getvalue()

# de-serialize a numpy array from bytes
def bytes_to_array(b: bytes) -> np.ndarray:
    np_bytes = BytesIO(b)
    return np.load(np_bytes, allow_pickle=True)

class ArrayShare:
    """One Shamir share of an array. Stores its x coordinate, and an array of y coordinates,
       one y coordinate per element of the original array. All of the x coordinates must match."""
    def __init__(self, x, ys, T, GF, K=1, encrypted=False):
        self.x = x
        self.ys = ys
        self.GF = GF
        self.T = T
        self.K = K
        self.encrypted = encrypted

    def encrypt(self, sk, pk):
        assert not self.encrypted
        b = array_to_bytes(self.ys)
        enc_b = Box(sk, pk).encrypt(b)
        return ArrayShare(self.x, enc_b, self.T, self.GF, K=self.K, encrypted=True)

    def decrypt(self, sk, pk):
        assert self.encrypted
        m = Box(sk, pk).decrypt(self.ys)
        array = bytes_to_array(m)
        return ArrayShare(self.x, array, self.T, self.GF, K=self.K, encrypted=False)


    def __str__(self):
        return f'ArrayShare(x={self.x}, len={len(self.ys)}, T={self.T}, K={self.K}, enc={self.encrypted})'

    __repr__ = __str__

def reshape(secrets, K, GF):
    if len(secrets) %K == 0:
        return secrets.reshape((len(secrets)//K, K))

    true_len = (len(secrets)//K + 1) * K
    flat_pad = GF.Zeros((true_len))
    flat_pad[:len(secrets)] = secrets
    return flat_pad.reshape((len(secrets)//K + 1), K)

def share_packed(secrets, range_shares, T, K, GF):
    """
    secrets: flat array
    """
    secrets = reshape(secrets, K, GF)
    secrets = np.atleast_2d(secrets)
    p_size = (secrets.shape[0], K + T - 1)

    poly_points = GF.Random((p_size))
    poly_points[:, :K] = secrets
    xs = GF.Range(0, p_size[1])
    polys = [galois.lagrange_poly(xs, pps) for pps in poly_points]
    shares = {x: ArrayShare(x+K, GF(np.array([poly(x+K) for poly in polys])), T, GF, K=K) \
              for x in range_shares}
    return shares

def share_array(secrets, range_shares, T, GF, K=1):
    """Secret shares an array of secrets. Returns a dict mapping the x coordinate of each share
       to an ArrayShare object with that x coordinate."""
    return share_packed(secrets, range_shares, T, K, GF)

def reconstruct_array(array_shares):
    """Given a list of ArrayShare objects, reconstructs the original array"""
    assert len(array_shares) > 0
    array_len = len(array_shares[0].ys)
    GF = array_shares[0].GF
    T = array_shares[0].T
    K = array_shares[0].K

    assert len(array_shares) >= T + K, f'we have {len(array_shares)} shares, and we need {T + K}'

    # Error checking
    for s in array_shares:
        assert len(s.ys) == array_len
        assert s.GF == GF
        assert s.T == T
        assert s.K == K

    # Reconstruction
    arr = []
    xs = GF([s.x for s in array_shares])
    for i in range(array_len):
        # TODO: check T
        ys = GF([s.ys[i] for s in array_shares])
        poly = galois.lagrange_poly(xs, ys)
        arr.extend([poly(i) for i in range(0, K)])

    return GF(arr)




def sum_share_array(shares):
    """Given a list of ArrayShare objects with matching x coordinates, returns a new
       ArrayShare object representing the column-wise sum of the input shares"""
    assert len(shares) > 0
    x = shares[0].x
    GF = shares[0].GF
    T = shares[0].T
    K = shares[0].K

    for s in shares:
        assert not s.encrypted
        assert s.x == x
        assert s.GF == GF
        assert s.T == T
        assert s.K == K

    share_matrix = GF([s.ys for s in shares])
    sum_ys = share_matrix.sum(axis=0)

    return ArrayShare(x, sum_ys, T, GF, K=K, encrypted=False)

def prof():
    for _ in range(1):
        GF = galois.GF(2**31-1)
        vals = GF(np.random.randint(5, 6, 500))
        shares = share_array(vals, range(1,65), 4, GF, K=50)
        #print(shares)
        r = reconstruct_array(list(shares.values()))
        print(r)

if __name__ == '__main__':
    prof()
    #cProfile.run('prof()', sort='cumtime')
