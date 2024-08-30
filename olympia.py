import argparse
import os
import importlib

from pick import pick

from config.base_config import BaseConfig


if __name__ == '__main__':

  

  # Test command line parameters.  Only peel off the config file.
  # Anything else should be left FOR the config file to consume as agent
  # or experiment parameterization.
  parser = argparse.ArgumentParser(description='Simulation configuration.')
  parser.add_argument('-c', '--config',
                      help='Name of config file to execute')
  parser.add_argument('--config-help', action='store_true',
                    help='Print argument options for the specific config file.')

  args, config_args = parser.parse_known_args()

  # First parameter supplied is config file.
  config_file = args.config
  if config_file is None:
    title = 'Please choose which protocol you want to simulate: '
    options = list(filter(lambda x: x[-4:] == "yaml", os.listdir('config')))
    config_file, index = pick(options, title, indicator='=>', default_index=0)
    args.config = config_file
  print("CONFIG FILE: ", config_file)

  if config_file[-4:] == "yaml":
    config = BaseConfig(os.path.join("config", f"{config_file}"))
    config.run_config()
  else:
    config = importlib.import_module('config.{}'.format(config_file),
                                   package=None)

