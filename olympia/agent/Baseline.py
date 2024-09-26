from olympia.agent.AggregationAgent import AggregationClient, DropoutAggregationServer
import numpy as np 

class BaselineClientAgent(AggregationClient):
    def round(self, round_number, message):
        if round_number == 1:
            self.GF = self.params['gf']
            self.random_state = self.params['random_state']
            client_value = self.GF(np.ones(self.params['dim'], dtype=int))
            return client_value

class BaselineServiceAgent(DropoutAggregationServer):
    # dropout_fraction = 0.05

    def round(self, round_number, messages):
        if round_number == 1:
            return {client: None for client in self.clients}

        elif round_number == 2:
            GF = self.params['gf']
            self.succeed(result = GF(list(messages.values())).sum(axis=0))

