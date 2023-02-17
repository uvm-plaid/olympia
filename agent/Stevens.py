from agent.AggregationAgent import AggregationClient, DropoutAggregationServer
from nacl.public import PrivateKey, Box
import util.shamir_sharing as shamir
from util import util
from util.util import log_print
from collections import defaultdict
import numpy as np

class StevensClientAgent(AggregationClient):
    def round(self, round_number, message):
        if round_number == 1: 

            ################ INITIALIZE #################
            self.GF = self.params['gf']
            self.random_state = self.params['random_state']
            # self.client_value = self.GF([10, 10, 10, 10, 10])  
            self.client_value = self.GF(self.random_state.randint(low = 0, high = 100,
                                                             size=self.params['dim']))
            self.s_len = self.params['s_len']
            self.frac_malicious = self.params['frac_malicious']

            self.A = make_A(self.params['dim'], self.s_len, self.GF, message)
            ##############################################

            self.s = self.make_s(self.s_len)               # generate keys
            self.sk_u = PrivateKey.generate()
            self.pk_u = self.sk_u.public_key
            self.masked_value = None
            return self.pk_u

        if round_number == 2:
            still_alive = list(sorted(message.keys()))
            n = len(still_alive)
            self.T = int(n*self.frac_malicious) + 1
            expected_dropouts = int(n*0.065)*4 + 1
            if self.params['packing']:
                self.K = n - self.T - expected_dropouts - 1
            else:
                self.K = 1
            self.mask_message()
            self.pks = message
            shares = shamir.share_array(self.s, still_alive, self.T, self.GF, K=self.K)
            enc_shares = {c: shares[c].encrypt(self.sk_u, pk)
                          for c, pk in self.pks.items()
                          if c in shares}
            return {"enc_shares" : enc_shares, "masked_value" : self.masked_value}
        
        if round_number == 3:
            dec_shares = [s.decrypt(self.sk_u, self.pks[c])
                          for c, s in message.items()
                          if c in self.pks]
            return shamir.sum_share_array(dec_shares)

    def mask_message(self):
        if self.masked_value == None:
            self.masked_value = self.client_value + self.A.dot(self.s)

    def make_s(self, n):
        return self.GF.Random(n)
        #self.s = GF.Ones(n)

class StevensServiceAgent(DropoutAggregationServer):
    dropout_fraction = 0.065

    def round(self, round_number, messages):
        if round_number == 1:
            self.GF = self.params['gf']
            self.s_len = self.params['s_len']
            self.threshold = len(self.clients)
            random_number = int(self.GF.Random(()))
            self.A = make_A(self.params['dim'], self.s_len, self.GF, random_number)
            return {client: random_number for client in self.clients}
        
        if round_number == 2:
            pks = messages
            all_pks = {client: pks for client in pks.keys()}
            return all_pks 

        if round_number == 3:
            out_shares = defaultdict(dict)
            self.masked_values = defaultdict(dict)
            for source in messages.keys():
                self.masked_values[source] = messages[source]['masked_value']
                for dest in messages[source]['enc_shares'].keys():
                    out_shares[dest][source] = messages[source]['enc_shares'][dest]
            return out_shares

        if round_number == 4:
            self.shares = messages
            u4 = set(self.shares.keys()).union(set(self.masked_values.keys()))
            mask_vals = self.GF([self.masked_values[k] for k in u4 if isinstance(self.masked_values[k],self.GF)])

            self.total = mask_vals.sum(axis=0)
            self.s = shamir.reconstruct_array(list(self.shares.values()))
            self.aggregate = self.total - self.A.dot(self.GF(self.s[:self.s_len]))
            self.succeed(result = self.aggregate)

def make_A(vec_size, n, GF, seed):
    return GF.Random((vec_size, n), seed = seed)
