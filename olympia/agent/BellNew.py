from olympia.agent.AggregationAgent import AggregationClient, DropoutAggregationServer
from nacl.public import PrivateKey, Box
import olympia.util.shamir_sharing as shamir
from olympia.util import util
from olympia.util.util import log_print
from collections import defaultdict
import numpy as np
import networkx as nx
import random
from networkx.generators.harary_graph import *
from olympia.util.merkle_tree import MerkleTree, VerificationTree
from typing import Dict, List, Tuple


class BellClientAgent(AggregationClient):
    def round(self, round_number, message):
        if round_number == 1:
            self.GF = self.params['gf']
            self.client_value = self.GF(np.ones(self.params['dim'], dtype=int))
            self.personal_seed = self.params['random_state'].randint(
                low=0, high=(2**31-1))

            self.clients = message['clients'].copy()
            self.clients.remove(self.id)
            self.k = message['k']

            # Generate Neighbors
            self.outgoing_neighbors = set(random.sample(self.clients, self.k))
            out_message = {}
            out_message['neighbors'] = self.outgoing_neighbors

            # Generate keys
            self.key1, self.pk1, self.signed_pk1 = self.generate_keys(self.params['signing_key'])
            self.key2, self.pk2, self.signed_pk2 = self.generate_keys(self.params['signing_key'])

            out_message['pk1'] = self.pk1
            out_message['signed_pk1'] = self.signed_pk1
            out_message['pk2'] = self.pk2
            out_message['signed_pk2'] = self.signed_pk2

            return out_message

        elif round_number == 2:
            self.incoming_neighbors = message['incoming_neighbors']
            self.neighbor_pk1 = message['pk1']
            self.neighbor_pk2 = message['pk2']
            self.outgoing_neighbors = self.outgoing_neighbors.intersection(set(self.neighbor_pk1.keys()))

            # verify signatures on public keys and merkle tree proofs
            if self.params['malicious']:
                for client, mes in message['signed_pk1'].items():
                    self.params['verification_keys'][client].verify(mes)
                for client, mes in message['signed_pk2'].items():
                    self.params['verification_keys'][client].verify(mes)

                for client, tree in message['verification_trees1'].items():
                    tree.verify(self.neighbor_pk1[client]._public_key)
                for client, tree in message['verification_trees2'].items():
                    tree.verify(self.neighbor_pk2[client]._public_key)

            # secret share my seed
            H_seed = shamir.share_array(self.GF([self.personal_seed]),
                                        self.outgoing_neighbors,
                                        len(self.outgoing_neighbors) // 2,
                                        self.GF)
            enc_H_seed = {c: s.encrypt(self.key2, self.neighbor_pk2[c])
                          for c, s in H_seed.items()}

            # secret share my sk
            sk_gf = util.bytes_to_field_array(self.key1._private_key, self.GF)
            H_sk = shamir.share_array(self.GF(sk_gf),
                                      self.outgoing_neighbors,
                                      len(self.outgoing_neighbors) // 2,
                                      self.GF)
            enc_H_sk = {c: s.encrypt(self.key2, self.neighbor_pk2[c])
                        for c, s in H_sk.items()}

            # send my shares
            outgoing_msg = {'h_seed': enc_H_seed,
                            'h_sk': enc_H_sk}
            return outgoing_msg

        elif round_number == 3:
            self.received_h_seed = message['h_seed']
            self.received_h_sk = message['h_sk']
            self.u2 = message['u2']

            # add the personal mask
            key = self.GF.Random((len(self.client_value)), seed=self.personal_seed)

            all_neighbors = self.outgoing_neighbors.union(self.incoming_neighbors)

            # add the neighbor masks
            current_ns = self.u2.intersection(all_neighbors)
            for j in current_ns:
                shared_key_box = Box(self.key1, self.neighbor_pk1[j])
                seed_ij = abs(hash31(shared_key_box.shared_key()))
                s_ij = self.GF.Random((len(self.client_value)), seed=seed_ij)

                if j < self.id:
                    key += s_ij

                elif j > self.id:
                    key -= s_ij

            # encode my masked value
            masked_value = self.client_value + key
            output_msg = {'masked_value': masked_value}

            # generate "included" signatures
            if self.params['malicious']:
                sigs = {}
                for j in current_ns:
                    m_ij = ('included', self.id, j)
                    m_ij_b = b'included' + self.id.to_bytes(3, 'little') + j.to_bytes(3, 'little')
                    sigma_ij = self.params['signing_key'].sign(m_ij_b)
                    sigs[j] = (m_ij, sigma_ij)
                output_msg['sigs'] = sigs

            return output_msg

        elif round_number == 4:
            assert message['Di'].intersection(message['Si']) == set()

            output_msg = {}

            # verify sigs
            if self.params['malicious']:
                for source in message['Si']:
                    (v, i, j), sig = message['sigs'][source]
                    assert v == 'included'
                    assert j == self.id
                    m_ij_b = b'included' + i.to_bytes(3, 'little') + j.to_bytes(3, 'little')
                    assert m_ij_b == self.params['verification_keys'][source].verify(sig)

            # generate "ack" signatures
            if self.params['malicious']:
                sigs = {}
                for j in message['Si']:
                    m_ij = ('ack', self.id, j)
                    m_ij_b = b'ack' + self.id.to_bytes(3, 'little') + j.to_bytes(3, 'little')
                    sigma_ij = self.params['signing_key'].sign(m_ij_b)
                    sigs[j] = (m_ij, sigma_ij)
                output_msg['sigs'] = sigs

            return output_msg

        elif round_number == 5:
            output_msg = {}

            # verify sigs
            if self.params['malicious']:
                for source in message['sigs'].keys():
                    (v, i, j), sig = message['sigs'][source]
                    assert v == 'ack'
                    assert j == self.id
                    m_ij_b = b'ack' + i.to_bytes(3, 'little') + j.to_bytes(3, 'little')
                    assert m_ij_b == self.params['verification_keys'][source].verify(sig)

            # decrypt shares of sk for dropouts (paper is wrong)
            outgoing_sk = {}
            for c in message['Di']:
                dec_h_sk = self.received_h_sk[c].decrypt(self.key2, self.neighbor_pk2[c])
                outgoing_sk[c] = dec_h_sk

            # decrypt shares of seed for survivors (paper is wrong)
            outgoing_seed = {}
            for c in message['Si']:
                dec_h_seed = self.received_h_seed[c].decrypt(self.key2, self.neighbor_pk2[c])
                outgoing_seed[c] = dec_h_seed

            output_msg['sk'] = outgoing_sk
            output_msg['seed'] = outgoing_seed

            return output_msg


class BellServiceAgent(DropoutAggregationServer):
    dropout_fraction = 0.05


    def round(self, round_number, messages):
        # print(f'server round number: {round_number}')
        # dropped_out_parties = sorted(list(set(range(1, len(
        #     self.clients) + 1)).difference(set(messages.keys())))) if round_number != 1 else []
        # print(f'Droped out #: {len(dropped_out_parties)}')
        # print(f'Droped out parties: {dropped_out_parties}')

        if round_number == 1:
            self.GF = self.params['gf']
            self.dim = self.params['dim']
            self.num_clients = self.params['num_clients']
            self.malicious = self.params['malicious']
            random_number = int(self.GF.Random(()))

            if self.num_clients <= 50:
                k_node_connectivity = self.num_clients-1
            else:
                k_node_connectivity = 50

            return {client: {'clients': self.clients,
                             'k': k_node_connectivity,
                             'a_seed': random_number}
                    for client in self.clients}

        if round_number == 2:
            self.pk1s = {}
            self.pk2s = {}
            self.outgoing_neighbors = {}
            self.incoming_neighbors = {}

            if self.malicious:
                self.signed_pk1s = {}
                self.signed_pk2s = {}

            self.u1 = set(messages.keys())

            # save public keys and incoming neighbors
            for c, m in messages.items():
                self.pk1s[c] = m['pk1']
                self.pk2s[c] = m['pk2']
                self.outgoing_neighbors[c] = set(m['neighbors']).intersection(self.u1)
                if self.malicious:
                    self.signed_pk1s[c] = m['signed_pk1']
                    self.signed_pk2s[c] = m['signed_pk2']

            self.incoming_neighbors = {c: set() for c in self.u1}

            # construct incoming neighbors
            for c, outgoing in self.outgoing_neighbors.items():
                for n in outgoing:
                    if n in self.u1:
                        self.incoming_neighbors[n].add(c)

            # construct the merkle tree
            if self.malicious:
                merkle_tree1 = MerkleTree()
                merkle_tree2 = MerkleTree()

                # Create the merkle tree
                for c in self.u1:
                    merkle_tree1.add_data(self.pk1s[c]._public_key)
                    merkle_tree2.add_data(self.pk2s[c]._public_key)

                # Send the verification trees to each client
                verification_trees1 = {}
                verification_trees2 = {}
                for i, c in enumerate(self.u1):
                    verification_trees1[c] = merkle_tree1.get_verification_tree(i)
                    verification_trees2[c] = merkle_tree2.get_verification_tree(i)

            # construct the message to each client
            outgoing_msg = {}
            for c in self.u1:
                all_ns = self.incoming_neighbors[c].union(self.outgoing_neighbors[c])
                outgoing_msg[c] = {}
                outgoing_msg[c]['incoming_neighbors'] = self.incoming_neighbors[c]
                outgoing_msg[c]['pk1'] = {o: self.pk1s[o] for o in all_ns}
                outgoing_msg[c]['pk2'] = {o: self.pk2s[o] for o in all_ns}
                if self.malicious:
                    outgoing_msg[c]['signed_pk1'] = {o: self.signed_pk1s[o] for o in all_ns}
                    outgoing_msg[c]['signed_pk2'] = {o: self.signed_pk2s[o] for o in all_ns}
                    outgoing_msg[c]['verification_trees1'] = {n: verification_trees1[n] for n in all_ns}
                    outgoing_msg[c]['verification_trees2'] = {n: verification_trees2[n] for n in all_ns}
                    outgoing_msg[c]['root_hash1'] = merkle_tree1.get_root_hash()
                    outgoing_msg[c]['root_hash2'] = merkle_tree2.get_root_hash()

            return outgoing_msg

        elif round_number == 3:
            self.u2 = self.u1.intersection(set(messages.keys()))

            outgoing_message = {c: {'h_seed': {},
                                    'h_sk': {}}
                                for c in self.u2}

            # route the shares to destination clients
            for source in messages.keys():
                for dest, share in messages[source]['h_seed'].items():
                    if dest in self.u2:
                        outgoing_message[dest]['h_seed'][source] = share
                for dest, share in messages[source]['h_sk'].items():
                    if dest in self.u2:
                        outgoing_message[dest]['h_sk'][source] = share

            for dest in self.u2:
                outgoing_message[dest]['u2'] = self.u2

            return outgoing_message

        elif round_number == 4:
            self.u3 = self.u2.intersection(set(messages.keys()))
            self.masked_values = self.GF([v['masked_value'] for v in messages.values()])

            self.survivors = self.u3
            self.dropouts = self.u2 - self.survivors

            # route signatures to destination clients
            if self.malicious:
                sigs = {c: v['sigs'] for c, v in messages.items()}
                inv_sigs = {c: {} for c in self.survivors}
                for source, v in sigs.items():
                    for dest, s in v.items():
                        if source in self.survivors and dest in self.survivors:
                            inv_sigs[dest][source] = s

            outgoing_msg = {}
            for c in self.survivors:
                outgoing_msg[c] = {'Di': self.incoming_neighbors[c].intersection(self.dropouts),
                                   'Si': self.incoming_neighbors[c].intersection(self.survivors)}
                if self.malicious:
                    outgoing_msg[c]['sigs'] = inv_sigs[c]

            return outgoing_msg

        elif round_number == 5:
            # route signatures to destination clients
            if self.malicious:
                sigs = {c: v['sigs'] for c, v in messages.items()}
                inv_sigs = {c: {} for c in self.survivors}
                for source, v in sigs.items():
                    for dest, s in v.items():
                        if source in self.survivors and dest in self.survivors:
                            inv_sigs[dest][source] = s

            outgoing_msg = {}
            for c in self.survivors:
                outgoing_msg[c] = {'Di': self.incoming_neighbors[c].intersection(self.dropouts),
                                   'Si': self.incoming_neighbors[c].intersection(self.survivors)}
                if self.malicious:
                    outgoing_msg[c]['sigs'] = inv_sigs[c]

            return outgoing_msg

        elif round_number == 6:
            received_sk = {c: [] for c in self.dropouts} # paper is wrong
            received_seed = {c: [] for c in self.survivors} # paper is wrong

            # aggregate the shares
            for v in messages.values():
                for c, share in v['sk'].items():
                    received_sk[c].append(share)
                for c, share in v['seed'].items():
                    received_seed[c].append(share)

            # reconstruct seeds
            seeds = {c: shamir.reconstruct_array(shares) for c, shares in received_seed.items()}
            sis = {c: self.GF.Random((self.masked_values.shape[1]), seed=int(seed))
                   for c, seed in seeds.items()}
            total_si = self.GF(list(sis.values())).sum(axis=0)

            key = total_si

            # reconstruct sks
            sks_gf = {c: shamir.reconstruct_array(shares) for c, shares in received_sk.items()}
            sks_b = {c: util.field_array_to_bytes(v, 32, self.GF) for c, v in sks_gf.items()}
            sks = {c: PrivateKey(s) for c, s in sks_b.items()}

            for i in sks.keys():
                all_ns = self.incoming_neighbors[i].union(self.outgoing_neighbors[i])
                for j in self.u2.intersection(all_ns):
                    shared_key_box = Box(sks[i], self.pk1s[j])
                    seed_ij = abs(hash31(shared_key_box.shared_key()))
                    s_ij = self.GF.Random((self.masked_values.shape[1]), seed=seed_ij)

                    if i < j:
                        key += s_ij

                    elif i > j:
                        key -= s_ij


            result = self.masked_values.sum(axis=0) - key

            # calculate the expected output
            expected = len(self.u3)

            # make sure it's correct
            for x in result:
                assert x == expected

            self.succeed(result=result)


def hash31(value):
    return hash(value) & (2**31-1)


def make_A(vec_size, n, GF, seed):
    return GF.Random((vec_size, n), seed=seed)
