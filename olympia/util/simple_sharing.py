import numpy as np
import galois
from numba import njit


def reshape(secrets, K, GF):
    if len(secrets) %K == 0:
        return secrets.reshape((len(secrets)//K, K))
    
    true_len = (len(secrets)//K + 1) * K
    flat_pad = GF.Zeros((true_len))
    flat_pad[:len(secrets)] = secrets
    return flat_pad.reshape((len(secrets)//K + 1), K)


def share(secrets, num_shares, T, K, GF):
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
    return GF([GF(np.array([poly(i) for i in np.arange(K, num_shares + K)])) for poly in polys])

def recon(shares, K, GF):
    result = []
    for share in shares:
        xs = GF.Range(K, len(share) + K)
        new_xs = GF([x for x, i in zip(xs, share) if i != 0])
        new_share = GF([x for x  in share if x != 0])
        poly = galois.lagrange_poly(new_xs, new_share)
        result.extend([poly(i) for i in range(K)])
    return result


def shareshare(secrets, num_shares, T, K, GF):
    shards = GF(share(secrets, 2, 2, 1, GF))
    g1 = share(shards[:, 0], num_shares, T, K, GF)
    g2 = share(shards[:, 1], num_shares, T, K, GF)
    return GF([g1, g2])

def reconrecon(shares, K, GF):
    s1 = recon(shares[0], K, GF)
    s2 = recon(shares[1], K, GF)
    shards = GF([s1, s2]).T
    secrets = recon(GF(shards), 1, GF)
    return secrets
