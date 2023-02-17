import argparse
import itertools
import os
import sys
import time

import galois
import geopandas as gpd
import numpy as np
import pandas as pd
import yaml

from Kernel import Kernel
from util import util
from pathlib import Path


class BaseConfig():
    def __init__(self, config_file):
        # Get Any Command Line Arguments
        parser = argparse.ArgumentParser(description='Detailed options config files.')
        parser.add_argument('-c', '--config',
                            help='Name of config file to execute')
        parser.add_argument('-l', '--log_dir', default=None,
                            help='Log directory name (default: unix timestamp at program start)')
        parser.add_argument('-s', '--seed', type=int, default=None,
                            help='numpy.random.seed() for simulation')
        parser.add_argument('-v', '--verbose', action='store_true',
                            help='Maximum verbosity!')
        parser.add_argument('--config_help', action='store_true',
                            help='Print argument options for this config file')
        parser.add_argument('--no_save', action='store_true',
                            help='Dont save the results')

        self.args, remaining_args = parser.parse_known_args()

        if self.args.config_help:
            parser.print_help()
            sys.exit()
        
        self.system_start_time = pd.Timestamp.now()
        print("*****SYSTEM START_TIME", self.system_start_time)
        
        util.silent_mode = not self.args.verbose
        
        # Read in the YAML Config File
        config = {}
        with open(config_file, "r") as stream:
            try:
                config = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)
                exit()
        self.num_clients = config['num_clients']
        self.dims = config['dims']
        self.num_trials = range(config['num_trials'])
        # self.midnight = config['midnight']
        self.midnight = pd.to_datetime(config['midnight'])
        self.protocol_name = config["protocol_name"]
        self.GF = galois.GF(2**31 - 1)
        self.default_computation_delay = 0 #1000000000 * config['default_computation_delay']
        # self.default_computation_delay = 1000000000 * config['default_computation_delay']
        self.result_filename = f'results/{self.protocol_name}_' + time.strftime('%H-%M-%S_%m-%d-%Y') + '.csv'
        self.params = config['params']        
        
        try:
            self.params['gf'] = self.GF
        except:
            self.params = {'gf': self.GF}

        if 'seed' in config:
            self.seed = config['seed']
        else:
            self.seed = int(pd.Timestamp.now().timestamp() * 1000000) % (2**32 - 1)

        print ("Silent mode: {}".format(util.silent_mode))
        print ("Configuration seed: {}\n".format(self.seed))

        #Get a reference to the classes you will use for this test
        self.server_class = get_class(config['protocol_location_server'])
        self.client_class = get_class(config['protocol_location_client'])

        #Read in latency tables
        # files = [os.path.join('data', f'2021-q{i}', 'gps_mobile_tiles.shp') for i in range(1,5)]
        # dfs = [gpd.read_file(f, rows=10000) for f in [os.path.join('data', f'2021-q4', 'gps_mobile_tiles.shp')]]#for f in files]
        # self.latency_table_df = pd.concat(dfs, ignore_index=True)

        #Get a set of all possible agent configurations based off the YAML settings
        self.participant_configurations = itertools.product(self.num_clients, self.dims, self.num_trials)
    
    def run_config(self):
        latency_file = 'latencys.npy'
        for num_clients, dim, trial_num in self.participant_configurations:
            print("==="*40)
            print(f"{self.protocol_name} Experiment {trial_num}: RUNNING FOR {num_clients} CLIENTS and {dim} Dimensions")
            dim = int(float(dim))
            num_clients = int(num_clients)
            np.random.seed(self.seed)

            kernel = Kernel(f"{self.protocol_name} Kernel", random_state = np.random.RandomState(seed=np.random.randint(low=0,high=(2**32), dtype=np.int64)))

            server_random_state = np.random.RandomState(seed=np.random.randint(low=0,high=(2**32), dtype=np.int64))
            self.params['dim'] = dim
            self.params['num_clients'] = num_clients
            
            agents = []
            agent_types = []
            a, b = 1, 1 + num_clients
            client_ids = list(range(a, b))
            server = self.server_class(0, f"{self.protocol_name} Service Agent 0", f"{self.protocol_name}ServiceAgent",
                                client_ids,
                                random_state = server_random_state,
                                params = self.params
                                )
            agents.extend([server])
            agent_types.extend([f"{self.protocol_name}ServiceAgent"])
            
            clients = []
            for i in range(a, b):
                self.params['random_state'] = np.random.RandomState(seed=np.random.randint(low=0,high=(2**32), dtype=np.int64))
                clients.append(self.client_class(i, f"{self.protocol_name} Client Agent {i}", f"{self.protocol_name}ClientAgent", params = self.params))
                
            agents.extend(clients)
            agent_types.extend([ f"{self.protocol_name}ClientAgent" for _ in range(a,b) ])

            # latency = util.generate_latency_matrix(self.latency_table_df.sample(len(agent_types)))

            if Path(latency_file).exists():
                all_latency = np.load(latency_file)
                latency = all_latency[:len(agent_types), :len(agent_types)] 

            else:
                latency = np.full((len(agent_types), len(agent_types)), 5000000000)

            noise = [ 0.25, 0.25, 0.20, 0.15, 0.10, 0.05 ]
            print("Latency: ", latency)

            kernel.runner(agents = agents, startTime = self.midnight, stopTime = self.midnight + pd.Timedelta('100:00:00'),
                    agentLatency = latency, latencyNoise = noise,
                    defaultComputationDelay = self.default_computation_delay,
                    log_dir = self.args.log_dir)
            
            stats = util.build_stats(server, clients, kernel)
            print(stats)
            dropout_wait = 0
            if not self.args.no_save:
                util.write_csv(self.result_filename, stats, num_clients, dim, dropout_wait)
        print("RESULT FINAL NAME: ", self.result_filename)
        # QUESTION: Should This Be System End Time?
        print("*****SYSTEM START_TIME", self.system_start_time)
        print("*****CONFIG FILE FINISHED RUNNING*****")


# Helper function to get a reference to the correct class based off of a string
# https://stackoverflow.com/questions/452969/does-python-have-an-equivalent-to-java-class-forname
def get_class( kls ):
    parts = kls.split('.')
    module = ".".join(parts[:-1])
    m = __import__( module )
    for comp in parts[1:]:
        m = getattr(m, comp)            
    return m

