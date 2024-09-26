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


class AcornClientAgent(AggregationClient):
    def round(self, round_number, message):
        if round_number == 1:
            self.GF = self.params['gf']
            self.s_len = self.params['s_len']
            self.client_value = self.GF(np.ones(self.params['dim'], dtype=int))
            self.A = self.GF.Random(
                (self.params['dim'], self.s_len), seed=message['a_seed'])
            self.personal_seed = self.params['random_state'].randint(
                low=0, high=(2**31-1))
            
            self.clients = message['clients'].copy()
            self.clients.remove(self.id)
            self.k = message['k']

            if self.params['malicious']:
                self.sk_u, self.pk_u, self.signed_pk_u = self.generate_keys(
                    self.params['signing_key'])
                message = {'pk': self.pk_u, 'signed_pk': self.signed_pk_u}
            else:
                self.sk_u, self.pk_u, self.signed_pk_u = self.generate_keys()
                message = {'pk': self.pk_u}

            # Generate Neighbors
            self.neighbors = random.sample(self.clients, self.k)
            message['neighbors'] = self.neighbors
            
            return message
        
        if round_number == 2:
            self.pks = message['pks']
            self.personal_mask = self.GF.Random(
                (self.s_len), seed=self.personal_seed)
            neighbor_key_shares = {}
            neighbor_key_shares_routes = defaultdict(dict)

            if self.params['malicious']:
                [self.params['verification_keys'][client].verify(
                    mes) for client, mes in message['pks_verification'].items()]
                [tree.verify(self.pks[client]._public_key) for client, tree in message['verification_trees'].items()]
                

            # Initialize Key to be a Galois Array of all zeros
            self.add_mask = self.GF([0 for _ in range(self.s_len)])
            self.subtract_mask = self.GF([0 for _ in range(self.s_len)])

            # Each client computes one seed for each other client: seedᵢⱼ = Agree(skᵢ, pkⱼ)
            for client_id, client_pk in self.pks.items():
                if client_id != self.id:
                    shared_key_box = Box(self.sk_u, client_pk)
                    # Seed_{ij} = Agree(sk_i, pk_i)
                    seed = abs(hash31(shared_key_box.shared_key()))
                    # Use this seed as the random seed to generate an array of size (s_len, 1)
                    mask_array = self.GF.Random((self.s_len), seed=seed)
                    neighbor_key_shares[client_id] = shamir.share_array(
                        self.GF([seed]), self.pks.keys(), len(self.pks) // 2, self.GF)
                    neighbor_key_shares[client_id] = {c: neighbor_key_shares[client_id][c].encrypt(self.sk_u, self.pks[c])
                                                      for c in self.pks}
                    for dest in self.pks.keys():
                        neighbor_key_shares_routes[dest][(
                            self.id, client_id)] = neighbor_key_shares[client_id][dest]
                    # k_i = Sum_{j < i}(F(seed_{ij})) - Sum_{j > i}(F(seed_{ij}))
                    if self.id > client_id:
                        self.add_mask += mask_array
                    elif self.id < client_id:
                        self.subtract_mask += mask_array

            # Each client computes their key: kᵢ = F(seedᵢ) + ∑(j < i) F(seedᵢⱼ) - ∑(j > i) F(seedᵢⱼ)
            self.key = self.personal_mask + self.add_mask - self.subtract_mask

            # Each client sends one share of seedᵢ to each neighbor, and one share of seedᵢⱼ for each j to each neighbor
            personal_seed_shares = shamir.share_array(
                self.GF([self.personal_seed]), self.pks.keys(), len(self.pks) // 2, self.GF)
            personal_seed_shares = {c: personal_seed_shares[c].encrypt(self.sk_u, self.pks[c])
                                    for c in self.pks}

            # Each client computes their masked value Encode(kᵢ, xᵢ) and sends it to the server
            self.masked_value = self.encode(
                key=self.key, value=self.client_value)
            return {'masked_value': self.masked_value, 'personal_seed_shares': personal_seed_shares, 'neighbor_key_shares': neighbor_key_shares_routes}
        if round_number == 3:
            self.personal_seed_shares_enc = message['personal_seed_shares']
            self.neighbor_key_shares_enc = message['neighbor_key_shares']
            self.dropouts = message['dropouts']

            # Technically Only need to decrypt the shares that are needed for the server
            self.personal_seed_shares_dec = {c: s.decrypt(self.sk_u, self.pks[c])
                                             for c, s in self.personal_seed_shares_enc.items() if c not in self.dropouts}
            self.neighbor_key_shares_dec = {c: {r: s.decrypt(self.sk_u, self.pks[c]) for r, s in self.neighbor_key_shares_enc[c].items() if r[1] in self.dropouts}
                                            for c in self.neighbor_key_shares_enc.keys()}

            return {'personal_seed_shares': self.personal_seed_shares_dec, 'neighbor_key_shares': self.neighbor_key_shares_dec}

    def encode(self, key, value):
        return self.A.dot(key) + value


class AcornServiceAgent(DropoutAggregationServer):
    dropout_fraction = 0.05


    def round(self, round_number, messages):
        print(f'server round number: {round_number}')
        dropped_out_parties = sorted(list(set(range(1, len(
            self.clients) + 1)).difference(set(messages.keys())))) if round_number != 1 else []
        print(f'Droped out #: {len(dropped_out_parties)}')
        print(f'Droped out parties: {dropped_out_parties}')

        if round_number == 1:
            self.GF = self.params['gf']
            self.s_len = self.params['s_len']
            self.dim = self.params['dim']
            self.num_clients = self.params['num_clients']
            self.malicious = self.params['malicious']
            random_number = int(self.GF.Random(()))
            self.A = self.GF.Random(
                (self.params['dim'], self.s_len), seed=random_number)
            
            if self.num_clients <= 50:
                k_node_connectivity = self.num_clients-1
            else:
                k_node_connectivity = 50

            return {client: {'clients': self.clients, 'k': k_node_connectivity, 'a_seed': random_number} for client in self.clients}

        if round_number == 2:
            self.pks = {}
            self.pks_verification = {}
            self.neighbor_incoming = defaultdict(list)
            self.neighbor_outgoing = defaultdict(list)
            self.neighbor_pks_src = {}
            client_messages = defaultdict(dict)

            for k, v in messages.items():
                self.pks[k] = v['pk']
                if self.malicious:
                    self.pks_verification[k] = v['signed_pk']
                self.neighbor_outgoing[k] = v['neighbors']
                for neighbor in v['neighbors']:
                    self.neighbor_incoming[neighbor].append(k)
            
            if self.malicious:
                merkle_tree: MerkleTree = MerkleTree()
                verification_trees: Dict[int: VerificationTree] = {
                    client: None for client in messages}

                # Create the merkle tree
                for client in sorted(list(messages.keys())):
                    merkle_tree.add_data(
                        messages[client]['pk']._public_key)

                # Send the verification trees to each client
                index = 0
                for client in sorted(list(messages.keys())):
                    verification_trees[client]: VerificationTree = merkle_tree.get_verification_tree(
                        index)
                    index += 1

            for c in self.pks.keys():
                neighbor_pks = {}
                neighbors = list(set(self.neighbor_incoming[c]).union(set(self.neighbor_outgoing[c])).intersection(set(messages.keys())))
                for neighbor in neighbors:
                    neighbor_pks[neighbor] = self.pks[neighbor]
                self.neighbor_pks_src[c] = neighbor_pks
                client_messages[c]['pks'] = neighbor_pks
                if self.malicious:
                    client_messages[c]['pks_verification'] = {neighbor: self.pks_verification[neighbor] for neighbor in neighbors}
                    client_messages[c]['verification_trees'] = {neighbor: verification_trees[neighbor] for neighbor in neighbors}

            self.dropouts = dropped_out_parties
            return client_messages

        if round_number == 3:
            self.masked_values = self.GF(
                [items['masked_value'] for items in messages.values()])
            self.personal_seed_shares = {
                c: items['personal_seed_shares'] for c, items in messages.items()}
            self.neighbor_key_shares = {
                c: items['neighbor_key_shares'] for c, items in messages.items()}

            message_routes = defaultdict(dict)

            # Server sends shares of personal seedᵢ to each neighbor
            for sender, shares in self.personal_seed_shares.items():
                for reciever in shares:
                    message_routes[reciever].setdefault('personal_seed_shares', {})[
                        sender] = shares[reciever]
                    
            # Server sends shares of neighbor keyᵢⱼ to each neighbor
            for sender in self.neighbor_key_shares:
                for reciever, shares in self.neighbor_key_shares[sender].items():
                    message_routes[reciever].setdefault(
                        'neighbor_key_shares', {})[sender] = shares

            # Server sends dropouts to each client
            self.dropouts = list(set(dropped_out_parties) - set(self.dropouts))
            for reciever in message_routes:
                message_routes[reciever]['dropouts'] = self.dropouts

            return message_routes

        if round_number == 4:
            self.personal_seed_shares = {
                c: items['personal_seed_shares'] for c, items in messages.items()}
            self.neighbor_key_shares = {
                c: items['neighbor_key_shares'] for c, items in messages.items()}

            # Server reconstructs seedᵢ for i ∈ S
            # personal_seed_shares -> { Sender: { Reciever: Share of Recivers Secret Sent to Sender } } (All same x value for each sender)
            # What we need is -> { Reciever: [All Shares] } (All shares of a different x value)
            self.personal_seeds = defaultdict(list)
            for sender in self.personal_seed_shares:
                for reciever in self.personal_seed_shares[sender]:
                    self.personal_seeds[reciever].append(
                        self.personal_seed_shares[sender][reciever])
            self.personal_seeds = {c: shamir.reconstruct_array(
                shares) for c, shares in self.personal_seeds.items()}

            # Server reconstructs all of seedᵢⱼ for all i ∈ S and j ∈ D
            # neighbor_key_shares -> { Sender: { Reciever: { (Client_With_Secret, Reciever): Share between Client_With_Secret and Reciver Sent to Sender } } } (All same x value for each sender)
            # What we need is -> { (Client_With_Secret, Reciver): [All Shares] } } (All shares of a different x value)
            self.neighbor_keys = defaultdict(list)
            for sender in self.neighbor_key_shares:
                for reciever in self.neighbor_key_shares[sender]:
                    for client_receiver_tuple in self.neighbor_key_shares[sender][reciever]:
                        self.neighbor_keys[client_receiver_tuple].append(
                            self.neighbor_key_shares[sender][reciever][client_receiver_tuple])
            self.neighbor_keys = {c: shamir.reconstruct_array(
                shares) for c, shares in self.neighbor_keys.items()}

            # Server computes k = ∑(i ∈ S) ( seedᵢ + ∑(j ∈ D, j < i) seedᵢⱼ - ∑(j ∈ D, j > i) seedᵢⱼ )
            key = self.GF([0 for i in range(self.s_len)])
            for i in self.personal_seeds.keys():
                key += self.GF.Random((self.s_len),
                                      seed=int(self.personal_seeds[i]))
                for j in [dropout for dropout in self.dropouts if dropout in list(set(self.neighbor_incoming[i]).union(set(self.neighbor_outgoing[i])))]:
                    if j < i:
                        key += self.GF.Random((self.s_len),
                                              seed=int(self.neighbor_keys[(i, j)]))
                    elif j > i:
                        key -= self.GF.Random((self.s_len),
                                              seed=int(self.neighbor_keys[(i, j)]))

            #  Server computes Decode(k, received-values for i ∈ S)
            result = self.decode(key, self.masked_values.sum(axis=0))
            self.succeed(result=result)

    def decode(self, key, value):
        return value - self.A.dot(key)


def hash31(value):
    return hash(value) & (2**31-1)


def make_A(vec_size, n, GF, seed):
    return GF.Random((vec_size, n), seed=seed)
