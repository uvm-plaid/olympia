from olympia.agent.AggregationAgent import AggregationClient, DropoutAggregationServer
from nacl.public import PrivateKey, Box
import olympia.util.simple_sharing as shamir
import olympia.util.shamir_sharing as shamir

from olympia.util import util
from collections import defaultdict
import numpy as np


class BonawitzClientAgent(AggregationClient):
    def round(self, round_number, message):
        self.GF = self.params['gf']
        self.random_state = self.params['random_state']
        self.add_mask = 0
        self.subtract_mask = 0

        if round_number == 1:                   # generate keys
            self.b_u = self.random_state.randint(
                low=1, high=100)  # personal mask seed

            if self.params['malicious']:
                self.signing_key = self.params['signing_key']
                self.sk_u, self.pk_u, self.signed_pk_u = self.generate_keys(
                    self.signing_key)
            else:
                self.sk_u, self.pk_u, self.signed_pk_u = self.generate_keys()
            message = {'public_key': self.pk_u, 'signed_public_key':
        self.signed_pk_u} if self.params['malicious'] else {'public_key': self.pk_u}
            return message

        elif round_number == 2:
            pk_m, u1 = message
            self.u1 = u1
            self.pks = {client: mes['public_key']
                            for client, mes in pk_m.items()} 
                         # generate encrypted secret shares
            if self.params['malicious']:
                self.signed_pks = [self.params['verification_keys'][client].verify(
                    mes['signed_public_key']) for client, mes in pk_m.items()]

            n_range = list(self.u1)
            self.b_u_shares = shamir.share_array(
                self.GF([self.b_u]), n_range, len(n_range)//2, self.GF)
            self.sk_u_shares = shamir.share_array(util.bytes_to_field_array(
                self.sk_u._private_key, self.GF), n_range, len(n_range)//2, self.GF)

            enc_bu_share = {c: s.encrypt(self.sk_u, self.pks[c])
                            for c, s in self.b_u_shares.items()}

            enc_sku_share = {c: s.encrypt(self.sk_u, self.pks[c])
                             for c, s in self.sk_u_shares.items()}

            return {'enc_bu_share': enc_bu_share, 'enc_sku_share': enc_sku_share}

        elif round_number == 3:                 # Submit masked values
            client_value = self.GF(np.ones(self.params['dim'], dtype=int))
            self.enc_bu_shares, self.enc_sku_shares, self.u2 = message

            for agent_id in self.u2:
                pk_v = self.pks[agent_id]
                shared_key_box = Box(self.sk_u, pk_v)
                s_uv = abs(hash31(shared_key_box.shared_key()))
                np.random.seed(s_uv)
                mask_array = np.random.randint(
                    low=0, high=100, size=self.params['dim'])

                if self.id > agent_id: 
                    self.add_mask += mask_array
                elif self.id < agent_id:
                    self.subtract_mask += mask_array

            # Add vector with seed b_u
            np.random.seed(self.b_u)
            self.p_u = np.random.randint(
                low=0, high=100, size=self.params['dim'])
            masked_value = client_value + self.GF(self.p_u)+ \
                self.GF(self.add_mask) - \
                self.GF(self.subtract_mask)

            return masked_value

        elif round_number == 4:                 # sum up the received shares
            self.u3 = message
            if self.params['malicious']:
                return self.signing_key.sign(bytes(self.u3))
            return True

        elif round_number == 5:                # sum up the received shares
            self.u4 = set(message.keys())
            if self.params['malicious']:
                [self.params['verification_keys'][client].verify(
                    signed_message) for client, signed_message in message.items()]

            dec_bu_share = {c: self.enc_bu_shares[c].decrypt(self.sk_u, self.pks[c])
                            for c in self.u2}

            dec_sku_share = {c: self.enc_sku_shares[c].decrypt(self.sk_u, self.pks[c])
                             for c in self.u2}

            # U2 \ U3
            sku_users = self.u2 - self.u3
            bu_users = self.u3
            assert self.u3 - self.u2 == set()

            # Filter bu and sku values to send to server
            bu_share = {k: dec_bu_share[k] for k in bu_users}
            sku_share = {k: dec_sku_share[k] for k in sku_users}

            return {'bu_share': bu_share, 'sku_share': sku_share}


class BonawitzServiceAgent(DropoutAggregationServer):
    # dropout_fraction = 0.05

    def round(self, round_number, messages):
        self.GF = self.params['gf']
        add_p_vu = 0
        subtract_p_vu = 0

        if round_number == 1:                          # start the protocol
            return {client: None for client in self.clients}

        elif round_number == 2:
            pks = messages
            self.all_pks = {client: pk['public_key']
                            for client, pk in pks.items()}
            self.u1 = set(self.all_pks.keys())

            return {client: (messages, self.u1) for client in self.u1}

        elif round_number == 3:                        # route shares to destination clients
            bu_out_shares = defaultdict(dict)
            sku_out_shares = defaultdict(dict)
            enc_bu_shares, enc_sku_shares = {}, {}
            for k, v in messages.items():
                enc_bu_shares[k] = v['enc_bu_share']
                enc_sku_shares[k] = v['enc_sku_share']

            self.u2 = self.u1.intersection(set(messages.keys()))

            # for source in messages.keys():
            for source in enc_bu_shares.keys():
                for dest, share in enc_bu_shares[source].items():
                    bu_out_shares[dest][source] = share

                for dest, share in enc_sku_shares[source].items():
                    sku_out_shares[dest][source] = share

            outgoing = {c: (bu_out_shares[c], sku_out_shares[c], self.u2)
                        for c in self.u2}
            return outgoing

        elif round_number == 4:                        # process dropouts from masked_vals
            self.u3 = self.u2.intersection(set(messages.keys()))
            self.masked_values = messages

            return {k: self.u3 for k in self.u3}

        elif round_number == 5:
            self.u4 = self.u3.intersection(set(messages.keys()))
            self.consistency_check = {
                client: messages for client in self.u4}
            return self.consistency_check

        elif round_number == 6:                        # reconstruct sum from received shares
            array = self.GF(list(self.masked_values.values()))
            self.total = array.sum(axis=0)

            # this is the shares of k's sku
            sku_shares = {k: [] for k in self.u2 - self.u3}
            # this is the shares of k's bu
            bu_shares = {k: [] for k in self.u3}

            # unpack the shares received
            for d in messages.values():
                for k, v in d['sku_share'].items():
                    sku_shares[k].append(v)
                for k, v in d['bu_share'].items():
                    bu_shares[k].append(v)

            # reconstruct the sku and bu values
            reconstructed_sku = {k: shamir.reconstruct_array(sku_shares[k])
                                 for k in sku_shares.keys()}
            reconstructed_bu = {k: shamir.reconstruct_array(bu_shares[k])
                                for k in bu_shares.keys()}

            # subtract the personal masks
            for k, i in reconstructed_bu.items():
                assert k in self.u3
                np.random.seed(int(i))
                p_u = np.random.randint(
                    low=0, high=100, size=self.params['dim'])
                self.total = self.total - self.GF(p_u)

            # subtract the pairwise masks
            for key, sku_value in reconstructed_sku.items():
                assert key in (self.u2 - self.u3)
                sk_u = util.field_array_to_bytes(sku_value, 32, self.GF)

                for agent_id in self.u3:
                    pk_v = self.all_pks[agent_id]
                    shared_key_box = Box(PrivateKey(sk_u), pk_v)
                    s_uv = abs(hash31(shared_key_box.shared_key()))
                    np.random.seed(s_uv)
                    p_vu = np.random.randint(
                        low=0, high=100, size=self.params['dim'])

                    if key > agent_id:
                        add_p_vu += p_vu
                    elif key < agent_id:
                        subtract_p_vu += p_vu

            self.total = self.total + \
                self.GF(add_p_vu) - self.GF(subtract_p_vu)


            # calculate the expected output
            expected = len(self.u3)

            # make sure it's correct
            for x in self.total:
                assert x == expected

            self.succeed(result=self.total)

# 31bit hash function


def hash31(value):
    return hash(value) & (2**31-1)
