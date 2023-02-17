# Olympia: A Simulation Framework for Evaluating the Concrete Scalability of Secure Aggregation Protocols

This repository contains the implementation of the Olympia framework for implementing and evaluating secure protocols. It also contains the implementations of several case-study protocols from the paper (in the `agent` directory). The paper describing Olympia is:

- [Olympia: A Simulation Framework for Evaluating the Concrete Scalability of Secure Aggregation Protocols](tbd). Ivoline C. Ngong, Nicholas Gibson, Joseph P. Near.

## Team

Development of the Olympia system is led by [Ivoline C. Ngong](https://ivolinengong.com/) with help from [Nicholas Gibson](https://github.com/NicholasGibsonUVM) and [Joseph P. Near](https://www.uvm.edu/~jnear/).

## How to Run
Olympia requires Python >3.8. You can install the dependencies with `pip install -r requirements.txt`.
Then, run the olympia.py file and select the config file you would like to use. You can specify the config file using command line arguments as well.

### Command Line Arguments
- -c, --config
    - Name of config file to execute
- -l, --log_dir
    - Log directory name (default: unix timestamp at program start)
- -s, --seed
    - numpy.random.seed() for simulation
- -v, --verbose
    - Maximum verbosity!
- --config_help
    - Print argument options for this config file
- --no_save
    - Dont save the results')

After running (as long as you haven't passed the no_save cla) a csv of the simulations result will be saved to the results folder with naming convention *Protocol-Name_Hour-Minute-Second_Month-Day-Year.csv*


## Creating Custom Config Files
Config files must be created in the config directory in order to be found by olympia.py. They are yaml files which contain the following pieces of information
- num_clients
    - A list of the number of clients you'd like to simulate
    - Ex: [10, 100] would run your simulation for 10 clients and then for 100 clients
- dims
    - A list of the length of each clients secret array per simulation
    - Ex: [10, 100] would run your simultion for clients with a secret array length of 10 and then for a secret array length of 100
- num_trials
    - The number of times you'd like to run each unique simulation setup
    - Ex: 5 would run each combination of num_clients and dims 5 times
- midnight
    - Sets the start time of your simulation
- protocol_name
    - Sets the name of your protocol
- protocol_location_client
    - Sets the location of your protocols client class
    - Ex: agent.Masking.MaskingClientAgent
- protocol_location_server
    - Sets the location of your protocols server class
    - Ex: agent.Masking.MaskingServerAgent
- default_computation_delay
    - Sets the default computation delay for your simulation
- params
    - A list of any special parameters neccasarcy for your protocol

### Example Config File
```yaml
num_clients:
  - 10
  - 100
  - 1000
dims:
  - 1e1
  - 1e2
num_trials: 5
midnight: 2022-06-02
protocol_name: Masking
protocol_location_client: agent.Masking.MaskingClientAgent
protocol_location_server: agent.Masking.MaskingServiceAgent
default_computation_delay: 5
params:
  s_len: 710
  k: 3
```

## Reproducing Paper Results

The experimental results in the paper were produced using the config files in the `config` directory. We ran each of the protocols to collect the results in CSV files, then graphed the results in the `Experiment_Graphs.ipynb` file. You can find the results from the paper in that notebook; to reproduce them from scratch, run the protocol experiments to generate the CSV files and then re-run the code in the notebook.

The complete results also require the latency matrix specifying latencies between pairs of clients. This file is very large, so we don't include it in the repository. To generate this file, download the [internet speed test dataset](https://www.kaggle.com/datasets/dhruvildave/ookla-internet-speed-dataset) and then use the `generate_latency_matrix` function in the `util/util.py` file. Zero latency will be used for the experiments if the file is missing.
