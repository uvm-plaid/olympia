from olympia.agent.AggregationAgent import AggregationClient, DropoutAggregationServer
from nacl.public import PrivateKey, Box
from nacl.signing import SigningKey, VerifyKey
import olympia.util.shamir_sharing as shamir
from olympia.util import util
from olympia.util.util import log_print
from collections import defaultdict
import numpy as np
from collections import Counter


class StevensClientAgent(AggregationClient):
    def round(self, round_number, message):
        if round_number == 1:

            ################ INITIALIZE #################
            self.GF = self.params['gf']
            self.random_state = self.params['random_state']
            # self.client_value = self.GF([10, 10, 10, 10, 10])
            # self.client_value = self.GF(self.random_state.randint(low=0, high=100,
            #                                                       size=self.params['dim']))
            
            self.client_value = self.GF(np.ones(self.params['dim'], dtype=int))

            self.s_len = self.params['s_len']
            self.frac_malicious = self.params['frac_malicious']

            self.A = make_A(self.params['dim'], self.s_len, self.GF, message)
            ##############################################

            self.s = self.make_s(self.s_len)               # generate keys
            self.masked_value = None
            if self.params['malicious']:
                self.sk_u, self.pk_u, self.signed_pk_u = self.generate_keys(
                    self.params['signing_key'])
            else:
                self.sk_u, self.pk_u, self.signed_pk_u = self.generate_keys()
            message = {'public_key': self.pk_u, 'signed_public_key': self.signed_pk_u} if self.params['malicious'] else self.pk_u
            return message

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
            if self.params['malicious']:
                self.pks = {client: mes['public_key'] for client, mes in message.items()}
                self.signed_pks = [self.params['verification_keys'][client].verify(mes['signed_public_key']) for client, mes in message.items()]
            else:
                self.pks = message

            shares = shamir.share_array(self.s, still_alive, self.T, self.GF, K=self.K)
            enc_shares = {c: shares[c].encrypt(self.sk_u, pk) for c, pk in self.pks.items() if c in shares}
            return {"enc_shares": enc_shares, "masked_value": self.masked_value}

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
        # self.s = GF.Ones(n)


class StevensServiceAgent(DropoutAggregationServer):
    # dropout_fraction = 0.02

    def round(self, round_number, messages):
        if round_number == 1:
            self.GF = self.params['gf']
            self.s_len = self.params['s_len']
            self.malicious = self.params['malicious']
            self.threshold = len(self.clients)
            random_number = int(self.GF.Random(()))
            self.A = make_A(self.params['dim'],
                            self.s_len, self.GF, random_number)
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
            mask_vals = self.GF([self.masked_values[k] for k in u4 if isinstance(
                self.masked_values[k], self.GF)])

            self.total = mask_vals.sum(axis=0)
            self.s_a = shamir.reconstruct_array(
                list(self.shares.values())[:-1])
            
            self.aggregate_a = self.total - \
                self.A.dot(self.GF(self.s_a[:self.s_len]))
            
            if self.malicious:
                self.s_b = shamir.reconstruct_array(list(self.shares.values()))
                self.aggregate_b = self.total - \
                    self.A.dot(self.GF(self.s_b[:self.s_len]))
            
                assert check_list_equal(
                    self.aggregate_a, self.aggregate_b), "Protocol Failure: Malicious clients have different results"

            self.succeed(result=self.aggregate_a)


def make_A(vec_size, n, GF, seed):
    return GF.Random((vec_size, n), seed=seed)


def check_list_equal(a, b):
    equality_list = [e_a == e_b for e_a, e_b in zip(a, b)]
    return equality_list.count(True) == len(a)
