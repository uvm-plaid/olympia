from agent.AggregationAgent import AggregationClient, DropoutAggregationServer
from nacl.public import PrivateKey, Box
import util.shamir_sharing as shamir

from util import util
from collections import defaultdict

class ShamirClientAgent(AggregationClient):
    def round(self, round_number, message):
        self.GF = self.params['gf']
        self.random_state = self.params['random_state']

        if round_number == 1:                   # generate keys
            self.sk_u = PrivateKey.generate()
            self.pk_u = self.sk_u.public_key
            return self.pk_u

        elif round_number == 2:                 # generate encrypted secret shares
            client_value = self.GF(self.random_state.randint(low = 0, high = 100,
                                                             size=self.params['dim']))
            self.pks = message
            n_range = list(sorted(self.pks.keys()))
            shares = shamir.share_array(client_value, n_range, len(n_range)//2, self.GF)
            enc_shares = {c: shares[c].encrypt(self.sk_u, pk)
                          for c, pk in self.pks.items()
                          if c in shares}
            return enc_shares

        elif round_number == 3:                 # sum up the received shares
            dec_shares = [s.decrypt(self.sk_u, self.pks[c])
                          for c, s in message.items()
                          if c in self.pks]
            return shamir.sum_share_array(dec_shares)


class ShamirServiceAgent(DropoutAggregationServer):
    dropout_fraction = 0.05

    def round(self, round_number, messages):
        self.GF = self.params['gf']

        if round_number == 1:                          # start the protocol
            return {client: None for client in self.clients}

        elif round_number == 2:                        # broadcast received public keys
            all_pks = {client: messages for client in self.clients}
            return all_pks

        elif round_number == 3:                        # route shares to destination clients
            out_shares = defaultdict(dict)
            for source in messages.keys():
                for dest in messages[source].keys():
                    out_shares[dest][source] = messages[source][dest]
            return out_shares

        elif round_number == 4:                        # reconstruct sum from received shares
            result = shamir.reconstruct_array(list(messages.values()))
            self.succeed(result   = [int(x) for x in result])
