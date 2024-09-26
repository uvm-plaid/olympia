import math
import numpy as np
import pandas as pd
from contextlib import contextmanager
import warnings
from scipy.spatial.distance import pdist, squareform
import pandas as pd
import networkx as nx
import geopy.distance
import warnings
from olympia.message.Message import Message
from nacl.public import PublicKey, EncryptedMessage
from nacl.signing import SignedMessage
from galois import Array
from os.path import exists
from io import BytesIO
from olympia.util.merkle_tree import VerificationTree
from tqdm import tqdm
import sys

import olympia.util.shamir_sharing as shamir

# General purpose utility functions for the simulator, attached to no particular class.
# Available to any agent or other module/utility.  Should not require references to
# any simulator object (kernel, agent, etc).

# Module level variable that can be changed by config files.
silent_mode = False


# This optional log_print function will call str.format(args) and print the
# result to stdout.  It will return immediately when silent mode is active.
# Use it for all permanent logging print statements to allow fastest possible
# execution when verbose flag is not set.  This is especially fast because
# the arguments will not even be formatted when in silent mode.
def log_print (str, *args):
  if not silent_mode: print (str.format(*args))


# Accessor method for the global silent_mode variable.
def be_silent ():
  return silent_mode


# Utility method to flatten nested lists.
def delist(list_of_lists):
    return [x for b in list_of_lists for x in b]

# Utility function to get agent wake up times to follow a U-quadratic distribution.
def get_wake_time(open_time, close_time, a=0, b=1):
    """ Draw a time U-quadratically distributed between open_time and close_time.
        For details on U-quadtratic distribution see https://en.wikipedia.org/wiki/U-quadratic_distribution
    """
    def cubic_pow(n):
        """ Helper function: returns *real* cube root of a float"""
        if n < 0:
            return -(-n) ** (1.0 / 3.0)
        else:
            return n ** (1.0 / 3.0)

    #  Use inverse transform sampling to obtain variable sampled from U-quadratic
    def u_quadratic_inverse_cdf(y):
        alpha = 12 / ((b - a) ** 3)
        beta = (b + a) / 2
        result = cubic_pow((3 / alpha) * y - (beta - a)**3 ) + beta
        return result

    uniform_0_1 = np.random.rand()
    random_multiplier = u_quadratic_inverse_cdf(uniform_0_1)
    wake_time = open_time + random_multiplier * (close_time - open_time)

    return wake_time

def numeric(s):
    """ Returns numeric type from string, stripping commas from the right.
        Adapted from https://stackoverflow.com/a/379966."""
    s = s.rstrip(',')
    try:
        return int(s)
    except ValueError:
        try:
            return float(s)
        except ValueError:
            return s

def get_value_from_timestamp(s, ts):
    """ Get the value of s corresponding to closest datetime to ts.

        :param s: pandas Series with pd.DatetimeIndex
        :type s: pd.Series
        :param ts: timestamp at which to retrieve data
        :type ts: pd.Timestamp

    """

    ts_str = ts.strftime('%Y-%m-%d %H:%M:%S')
    s = s.loc[~s.index.duplicated(keep='last')]
    locs = s.index.get_loc(ts_str, method='nearest')
    out = s[locs][0] if (isinstance(s[locs], np.ndarray) or isinstance(s[locs], pd.Series)) else s[locs]

    return out

@contextmanager
def ignored(warning_str, *exceptions):
    """ Context manager that wraps the code block in a try except statement, catching specified exceptions and printing
        warning supplied by user.

        :param warning_str: Warning statement printed when exception encountered
        :param exceptions: an exception type, e.g. ValueError

        https://stackoverflow.com/a/15573313
    """
    try:
        yield
    except exceptions:
        warnings.warn(warning_str, UserWarning, stacklevel=1)
        if not silent_mode:
            print(warning_str)


def generate_uniform_random_pairwise_dist_on_line(left, right, num_points, random_state=None):
    """ Uniformly generate points on an interval, and return numpy array of pairwise distances between points.

    :param left: left endpoint of interval
    :param right: right endpoint of interval
    :param num_points: number of points to use
    :param random_state: np.RandomState object


    :return:
    """

    x_coords = random_state.uniform(low=left, high=right, size=num_points)
    x_coords = x_coords.reshape((x_coords.size, 1))
    out = pdist(x_coords, 'euclidean')
    return squareform(out)


def meters_to_light_ns(x):
    """ Converts x in units of meters to light nanoseconds

    :param x:
    :return:
    """
    x_lns = x / 299792458e-9
    x_lns = x_lns.astype(int)
    return x_lns


def validate_window_size(s):
    """ Check if s is integer or string 'adaptive'. """
    try:
        return int(s)
    except ValueError:
        if s.lower() == 'adaptive':
            return s.lower()
        else:
            raise ValueError(f'String {s} must be integer or string "adaptive".')


def sigmoid(x, beta):
    """ Numerically stable sigmoid function.
    Adapted from https://timvieira.github.io/blog/post/2014/02/11/exp-normalize-trick/"
    """
    if x >= 0:
        z = np.exp(-beta*x)
        return 1 / (1 + z)
    else:
        # if x is less than zero then z will be small, denom can't be
        # zero because it's 1+z.
        z = np.exp(beta*x)
        return z / (1 + z)

def generate_latency_matrix(sub_df):
    new_df = pd.DataFrame()
    latencies = []

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")

        sub_df["lon"] = sub_df["geometry"].centroid.x
        sub_df["lat"] = sub_df["geometry"].centroid.y

    for i in tqdm(range(sub_df.shape[0]), desc="Generating Latency Matix"):
        for j in range(sub_df.shape[0]):
            combined_latency = sub_df['avg_lat_ms'].iloc[i] + sub_df['avg_lat_ms'].iloc[j]
            distanceAB = geopy.distance.geodesic((sub_df['lat'].iloc[i] ,sub_df['lon'].iloc[i] ), (sub_df['lat'].iloc[j],sub_df['lon'].iloc[j] )).km
            latencyAB = (0.015 * distanceAB) + combined_latency # 0.015 = speedOfLight distance according to https://blog.scaleway.com/understanding-network-latency/

            key_A = sub_df['quadkey'].iloc[i]
            key_B = sub_df['quadkey'].iloc[j]
            
            latencies.append({"A":key_A, "B":key_B, "latencyAB":latencyAB})

    new_df = pd.DataFrame(latencies)
    # Create matrix
    G = nx.from_pandas_edgelist(new_df.rename(columns={'latencyAB':'weight'}), 
                                source='A', 
                                target='B', 
                                edge_attr ='weight')

    G.edges(data=True)
    adj = nx.to_pandas_adjacency(G)

    return adj.to_numpy() * 1000000 # convert from ms to ns

# Compute the size in bytes of a message
def get_msg_size(msg):
    if isinstance(msg, dict):
        # size of dict is size of values (ignore keys)
        return sum([get_msg_size(x) for x in msg.values()])
    elif isinstance(msg, Message):
        # size of message is size of values (ignore keys)
        return sum([get_msg_size(x) for x in msg.body.values()])
    elif isinstance(msg, (list, set)):
        # size of list is size of values
        return sum([get_msg_size(x) for x in msg])
    elif isinstance(msg, str):
        # size of string is its length (assume 1 byte encoding)
        return len(msg)
    elif isinstance(msg, (PublicKey, EncryptedMessage, SignedMessage)):
        return len(bytes(msg))
    elif isinstance(msg, Array):
        return (int(get_bytes_for_int(msg._characteristic)) + 1)*len(msg)
    elif isinstance(msg, tuple):  
        return sum([get_msg_size(x) for x in msg])
    elif isinstance(msg, shamir.ArrayShare):
        return (int(get_bytes_for_int(msg.GF._characteristic)) + 1)*len(msg.ys)
    elif msg == None:
        return 1
    elif isinstance(msg, (int, float)):
        # size of int and float is 64 bits
        return 8
    elif isinstance(msg, VerificationTree):
        return sys.getsizeof(msg)

    raise RuntimeError(f'Failed to compute message size for unknown message of type {type(msg)}: {msg}')

# Compute the number of bytes required to hold a particular integer
# (for finite fields)
def get_bytes_for_int(i):
    n = 1
    while 2**n < i:
        n += 1
    return int(n/8) + 1

# Convert nanoseconds to milliseconds
def ns_to_ms(x):
    return x / 1e6

# Build a dict with the results for an experiment
def build_stats(server, clients, kernel):
    survived_clients           = server.survived_clients 
    survived_clients_indices   = list(map(int, survived_clients))
    survived_clients_list      = [clients[i-1] for i in survived_clients_indices]
    avgClientComputationTime = ns_to_ms(np.mean([c.total_computation_time for c in survived_clients_list]))
    # avgClientComputationTimes   = ns_to_ms(np.mean([c.total_computation_time for c in clients]))
    serverComputationTime      = ns_to_ms(server.total_computation_time)
    totalTime                  = (kernel.currentTime - kernel.startTime).total_seconds() * 1000
    avgClientBytesSent         = np.mean([c.total_bytes_sent for c in clients])
    avgClientBytesReceived     = np.mean([c.total_bytes_received for c in clients])
    serverBytesSent            = server.total_bytes_sent
    serverBytesReceived        = server.total_bytes_received
    totalDropouts              = server.total_dropouts
    failure                    = server.failure
    dropoutFraction           = server.total_dropout_fraction
    serverRoundTimes           = server.server_round_times
    avgClientRoundRimes        = np.mean([c.client_round_times for c in clients])

    return {
        'avg client computation time (ms)': avgClientComputationTime,
        'server computation time (ms)': serverComputationTime,
        'total time (ms)': totalTime,
        'avg client bytes sent': avgClientBytesSent,
        'avg client bytes received': avgClientBytesReceived,
        'server bytes sent': serverBytesSent,
        'server bytes recieved': serverBytesReceived,
        'total dropouts': totalDropouts,
        'dropout fraction': dropoutFraction,
        'failure': failure,
        'server round times': serverRoundTimes,
        'avg client round times': avgClientRoundRimes,
        }

# Write an experiment result to a CSV file
def write_csv(filename, stats, num_clients, dim, dropout_wait):
    stat_fields = [
        'avg client computation time (ms)',
        'server computation time (ms)',
        'total time (ms)',
        'avg client bytes sent',
        'avg client bytes received',
        'server bytes sent',
        'server bytes recieved',
        'total dropouts',
        'dropout fraction',
        'failure',
        #'server round times',
        'avg client round times'
        ]

    stats_line = ','.join([str(round(stats[f], 2)) for f in stat_fields])
    line = f'{num_clients},{dim},{dropout_wait},{stats_line}'

    if not exists(filename):
        stats_header = ','.join(stat_fields)
        header = f'clients,dimension,dropout wait,{stats_header}'
        with open(filename, 'w') as f:
            f.write(header + '\n')
            f.write(line + '\n')
    else:
        with open(filename, 'a') as f:
            f.write(line + '\n')


# convert a numpy array to bytes
def array_to_bytes(x: np.ndarray) -> bytes:
    np_bytes = BytesIO()
    np.save(np_bytes, x, allow_pickle=True)
    return np_bytes.getvalue()

# de-serialize a numpy array from bytes
def bytes_to_array(b: bytes) -> np.ndarray:
    np_bytes = BytesIO(b)
    return np.load(np_bytes, allow_pickle=True)

def bytes_per_element(GF):
    n = 1
    while 2**(8*(n+1)) < GF.characteristic:
        n += 1
    return n


def bytes_to_field_array(b, GF):
    # how many bytes can we encode?
    n = bytes_per_element(GF)

    # split the bytes into chunks of size n bytes
    byte_chunks = [b[i:i+3] for i in range(0, len(b), n)]

    # convert each byte chunk to an int
    int_chunks = [int.from_bytes(b, "little") for b in byte_chunks]
    
    # return a field array of the int chunks
    return GF(int_chunks)


def field_array_to_bytes(arr, original_length, GF):
    n = bytes_per_element(GF)

    # convert each field element to int
    int_arr = [int(x) for x in arr]

    # convert each int to bytes
    byte_arr = [x.to_bytes(n, "little") for x in int_arr]

    # turn the bytes into a byte array
    all_bytes = b''.join(byte_arr)

    # truncate the byte array to its original length
    return all_bytes[0:original_length]
