from olympia.agent.AggregationAgent import AggregationClient, DropoutAggregationServer
from nacl.public import PrivateKey, Box
import olympia.util.shamir_sharing as shamir
from olympia.util import util
from olympia.util.merkle_tree import MerkleTree, VerificationTree
from olympia.util.util import log_print
from collections import defaultdict
import numpy as np
import networkx as nx
import random
from collections import defaultdict
from typing import Dict, List, Set, Tuple


class SharingSharingClientAgent(AggregationClient):
    def round(self, round_number, message):
        if round_number == 1:
            self.GF = self.params['gf']
            self.G = self.params['group_size']
            self.M = self.params['share_number']
            self.s_len = self.params['s_len']
            self.K = self.params['k']
            self.num_clients = message['num_clients']
            self.A = make_A(
                self.params['dim'], self.s_len, self.GF, message['a_seed'])
            if self.params['malicious']:
                self.sk_u, self.pk_u, self.signed_pk_u = self.generate_keys(
                    self.params['signing_key'])
            else:
                self.sk_u, self.pk_u, self.signed_pk_u = self.generate_keys()
            message = {'public_key': self.pk_u, 'signed_public_key':
        self.signed_pk_u} if self.params['malicious'] else {'public_key': self.pk_u}
            return message

        elif round_number == 2:
            self.client_value = self.GF(np.ones(self.params['dim'], dtype=int))
            self.pks = {client: mes['public_key'] for client, mes in message['pks'].items()}
            self.group_seed = message['seed']
            group_list = [i for i in range(1, self.num_clients + 1)]
            random.Random(self.group_seed).shuffle(group_list)
            num_groups = (self.num_clients // self.G)
            self.shuffled_id = group_list.index(self.id)
            j = self.shuffled_id % self.G
            self.group_1_id = self.shuffled_id // self.G
            self.group_2_id = (self.shuffled_id //self.G + j) % num_groups
            self.group_1_members = []
            self.group_2_members = []
            for client in sorted(message['pks'].keys()):
                client_shuffled_id = group_list.index(client)
                j = client_shuffled_id % self.G
                if client_shuffled_id // self.G == self.group_1_id:
                    self.group_1_members.append(client)
                if (client_shuffled_id // self.G + j) % num_groups == self.group_2_id:
                    self.group_2_members.append(client)

            if self.params['malicious']:
                [self.params['verification_keys'][client].verify(
                    mes['verification_key']) for client, mes in message['pks'].items()]
                message['verification_tree'].verify(self.pk_u._public_key)
                assert self.group_seed == message['verification_tree'].root_hash, "Protocol Failure: Malicious clients have different seeds"
                assert set(self.group_1_members + self.group_2_members) == set(message['pks'].keys()), "Protocol Failure: Malicious clients have different group members"

            self.S_group_1 = self.GF.Random(self.s_len)
            self.S_group_2 = self.GF.Random(self.s_len)

            # Generate High Level Shares
            self.high_level_share_one = self.GF(
                [self.GF.Random() for _ in self.client_value])
            self.high_level_share_two = self.GF(
                [x - y for x, y in zip(self.client_value, self.high_level_share_one)])

            # Generate Masked Values
            self.masked_value_group_1 = self.high_level_share_one + \
                self.A.dot(self.S_group_1)
            self.masked_value_group_2 = self.high_level_share_two + \
                self.A.dot(self.S_group_2)

            # Generate Shares
            shares_group_1 = shamir.share_array(self.S_group_1, range(
                len(self.group_1_members)), self.G // 2, self.GF, K=self.K)
            shares_group_2 = shamir.share_array(self.S_group_2, range(
                len(self.group_2_members)), self.G // 2, self.GF, K=self.K)

            # Encrypt the shares
            enc_shares_dict_group_1 = {m: shares_group_1[c].encrypt(self.sk_u, self.pks[m])
                                       for c, m in zip(shares_group_1, self.group_1_members)}
            enc_shares_dict_group_2 = {m: shares_group_2[c].encrypt(self.sk_u, self.pks[m])
                                       for c, m in zip(shares_group_2, self.group_2_members)}

            return {"group_1": {"enc_shares": enc_shares_dict_group_1, "masked_value": self.masked_value_group_1},
                    "group_2": {"enc_shares": enc_shares_dict_group_2, "masked_value": self.masked_value_group_2}}

        elif round_number == 3:
            enc_shares_group_1 = message['group_1']
            enc_shares_group_2 = message['group_2']

            dec_shares_group_1 = [s.decrypt(self.sk_u, self.pks[c])
                                  for c, s in enc_shares_group_1.items()]
            dec_shares_group_2 = [s.decrypt(self.sk_u, self.pks[c])
                                  for c, s in enc_shares_group_2.items()]

            su_group_1 = shamir.sum_share_array(dec_shares_group_1)
            su_group_2 = shamir.sum_share_array(dec_shares_group_2)

            return {'group_1': su_group_1, 'group_2': su_group_2}


class SharingSharingServiceAgent(DropoutAggregationServer):
    # dropout_fraction = 0.05

    def round(self, round_number, messages):
        print(f'server round number: {round_number}')
        dropped_out_parties = sorted(list(set(range(1, len(
            self.clients) + 1)).difference(set(messages.keys())))) if round_number != 1 else []
        print(f'Dropped out #: {len(dropped_out_parties)}')
        print(f'Dropped out parties: {dropped_out_parties}')
        if round_number == 1:
            self.GF = self.params['gf']
            self.G = self.params['group_size']
            self.M = self.params['share_number']
            self.s_len = self.params['s_len']
            self.K = self.params['k']
            self.malicious = self.params['malicious']
            a_seed = int(self.GF.Random(()))
            self.A = make_A(
                self.params['dim'], self.s_len, self.GF, a_seed)
            return {client: {'num_clients': len(self.clients), 'a_seed': a_seed} for client in self.clients}

        elif round_number == 2:
            client_messages = defaultdict(dict)
            seed = random.randint(0, 2**32)
            if self.malicious:
                merkle_tree: MerkleTree = MerkleTree()
                verification_trees: Dict[int: VerificationTree] = {client: None for client in messages}

                # Create the merkle tree
                for client in sorted(list(messages.keys())):
                    merkle_tree.add_data(
                        messages[client]['public_key']._public_key)

                # Send the verification trees to each client
                index = 0
                for client in sorted(list(messages.keys())):
                    verification_trees[client]: VerificationTree = merkle_tree.get_verification_tree(
                        index)
                    index += 1

                for client in sorted(list(messages.keys())):
                    client_messages[client]['verification_tree'] = verification_trees[client]

                seed = merkle_tree.get_root_hash()

            group_list = [i for i in range(1, len(self.clients) + 1)]
            random.Random(seed).shuffle(group_list)

            self.group_1 = defaultdict(list)
            self.group_2 = defaultdict(list)
            self.client_groups = {}
            num_groups = (len(self.clients) // self.G)
            for index, client in enumerate(group_list):
                if client in (dropped_out_parties):
                    continue
                j = index % self.G
                group_1_number = (index // self.G)
                group_2_number = (index //self.G + j) % num_groups
                self.group_1[group_1_number].append(client)
                self.group_2[group_2_number].append(client)
                self.client_groups[client] = (group_1_number, group_2_number)
                client_messages[client]['seed'] = seed

            for client in messages:
                group_list = set(self.group_1[self.client_groups[client][0]]).union(
                    set(self.group_2[self.client_groups[client][1]]))
                client_messages[client]['pks'] = {c: {'public_key': messages[c]['public_key']} if not self.malicious else {
                    'public_key': messages[c]['public_key'], 'verification_key': messages[c]['signed_public_key']}for c in group_list}

            return client_messages

        elif round_number == 3:
            # Send each client the shares of the other clients in it's group
            peer_exchange = {i: {'group_1': {}, 'group_2': {}}
                             for i in messages.keys()}
            self.masked_values_group_1 = {}
            self.masked_values_group_2 = {}

            # This O(Clients * Group_Size) which I think is the best we can get
            # Client 1 -> {
            #               Group 1: {
            #                           Client 1: {enc_shares},
            #                           Client 2: {enc_shares},
            #                           ...
            #                        },
            #               Group 2: {...}
            #             }
            # ...
            # Dictionarys have O(1) lookup time so that extra check to ensure the
            # sender hasn't dropped out shouldn't add any complexity
            for client in messages:
                peer_exchange[client]['group_1'] = {sender: messages[sender]['group_1']['enc_shares'][client]
                                                    for sender in self.group_1[self.client_groups[client][0]] if sender in messages}
                peer_exchange[client]['group_2'] = {sender: messages[sender]['group_2']['enc_shares'][client]
                                                    for sender in self.group_2[self.client_groups[client][1]] if sender in messages}
                self.masked_values_group_1[client] = messages[client]['group_1']['masked_value']
                self.masked_values_group_2[client] = messages[client]['group_2']['masked_value']
                # Save the masked values for each client for later on in the protocol

            return peer_exchange

        elif round_number == 4:
            self.shares_group_1 = {
                group: {'masked_vals': [], 'clients': {}} for group in self.group_1}
            self.shares_group_2 = {
                group: {'masked_vals': [], 'clients': {}} for group in self.group_2}

            # Get each groups shares
            for sender in messages:
                self.shares_group_1[self.client_groups[sender][0]]['clients'].update(
                    {sender: messages[sender]['group_1']})
                self.shares_group_2[self.client_groups[sender][1]]['clients'].update(
                    {sender: messages[sender]['group_2']})

            # Get each groups masked values
            u4_group_1 = set(messages.keys()).union(
                set(self.masked_values_group_1.keys()))
            u4_group_2 = set(messages.keys()).union(
                set(self.masked_values_group_2.keys()))
            for client_group_1, client_group_2 in zip(u4_group_1, u4_group_2):
                self.shares_group_1[self.client_groups[client_group_1][0]]['masked_vals'].append(
                    self.masked_values_group_1[client_group_1])
                self.shares_group_2[self.client_groups[client_group_1][1]]['masked_vals'].append(
                    self.masked_values_group_2[client_group_2])

            # Assert that the length of each group is greater than the threshold of reconstruction
            for group in self.shares_group_1:
                if len(self.shares_group_1[group]['clients']) < (self.G // 2) + self.K:
                    print(
                        f"Protocol Failure: Group {group} has exceded the possible number of dropouts for reconstruction")
                    exit()

            for group in self.shares_group_2:
                if len(self.shares_group_2[group]['clients']) < (self.G // 2) + self.K:
                    print(
                        f"Protocol Failure: Group {group} has exceded the possible number of dropouts for reconstruction")
                    exit()

            # Sum the masked values of each group
            for group in self.shares_group_1:
                self.shares_group_1[group]['masked_vals'] = self.GF(
                    self.shares_group_1[group]['masked_vals'])
                self.shares_group_1[group]['mask_val_total'] = self.shares_group_1[group]['masked_vals'].sum(
                    axis=0)
            for group in self.shares_group_2:
                self.shares_group_2[group]['masked_vals'] = self.GF(
                    self.shares_group_2[group]['masked_vals'])
                self.shares_group_2[group]['mask_val_total'] = self.shares_group_2[group]['masked_vals'].sum(
                    axis=0)

            missing_shares_group_1 = {x: set()
                                      for x in self.shares_group_1.keys()}
            group_sizes_1 = {group: len(x['clients'])
                             for group, x in self.shares_group_1.items()}
            for group in self.shares_group_1:
                x_values = set(
                    [share.x for share in self.shares_group_1[group]['clients'].values()])
                missing = set(range(self.G)).difference(x_values)
                for share in missing:
                    missing_shares_group_1[group].add(share)

            missing_shares_group_2 = {x: set()
                                      for x in self.shares_group_2.keys()}
            group_sizes_2 = {group: len(x['clients'])
                             for group, x in self.shares_group_2.items()}
            for group in self.shares_group_2:
                x_values = set(
                    [share.x for share in self.shares_group_2[group]['clients'].values()])
                missing = set(range(self.G)).difference(x_values)
                for share in missing:
                    missing_shares_group_2[group].add(share)

            threshold = (self.G // 2) + \
                2 if self.malicious else (self.G // 2) + 1

            reconstruction_groups_1, missing_x_values_1 = color_groups(
                missing_shares_group_1, group_sizes_1, threshold)
            reconstruction_groups_2, missing_x_values_2 = color_groups(
                missing_shares_group_2, group_sizes_2, threshold)

            # Reconstruct each groups secrets
            self.s_group_1 = self.reconstruct_secrets(
                reconstruction_groups_1, self.shares_group_1, missing_x_values_1)
            self.s_group_2 = self.reconstruct_secrets(
                reconstruction_groups_2, self.shares_group_2, missing_x_values_2)

            self.total_group_1 = self.unmask(
                [self.shares_group_1[group]['mask_val_total'] for group in self.shares_group_1.keys()], self.s_group_1)
            self.total_group_2 = self.unmask(
                [self.shares_group_2[group]['mask_val_total'] for group in self.shares_group_2.keys()], self.s_group_2)

            # Add the two groups together to reconstruct the answer
            result = self.total_group_1 + self.total_group_2

            if self.malicious:
                self.s_group_1_b = self.reconstruct_secrets(
                    reconstruction_groups_1, self.shares_group_1, missing_x_values_1, reduced=True)
                self.s_group_2_b = self.reconstruct_secrets(
                    reconstruction_groups_2, self.shares_group_2, missing_x_values_2, reduced=True)
                self.total_group_1_b = self.unmask(
                    [self.shares_group_1[group]['mask_val_total'] for group in self.shares_group_1.keys()], self.s_group_1_b)
                self.total_group_2_b = self.unmask(
                    [self.shares_group_2[group]['mask_val_total'] for group in self.shares_group_2.keys()], self.s_group_2_b)
                result_b = self.total_group_1_b + self.total_group_2_b
                assert check_list_equal(
                    result, result_b), "Protocol Failure: Malicious clients have different results"

            self.succeed(result=[int(x) for x in result])

    def reconstruct_secrets(self, recon_groups, shares_group, missing_x_values, reduced=False):
        s_group = {}
        for i, recon_group in enumerate(recon_groups):
            x_coord_shares = defaultdict(list)
            for group in recon_group:
                for array_share in shares_group[group]['clients'].values():
                    x_coord_shares[array_share.x].append(array_share)
            summed_x_coords = {x: shamir.sum_share_array(
                list(shares)) for x, shares in x_coord_shares.items() if x not in missing_x_values[i]}
            if reduced:
                s_group[i] = shamir.reconstruct_array(
                    list(summed_x_coords.values())[:-1])
            else:
                s_group[i] = shamir.reconstruct_array(
                    list(summed_x_coords.values()))
        return s_group

    def unmask(self, masked_values, secrets):
        summed_secrets = self.GF(list(secrets.values())).sum(axis=0)
        summed_masked_values = self.GF(list(masked_values)).sum(axis=0)
        return summed_masked_values - self.A.dot(summed_secrets[:self.s_len])


def encrypt_array(sk, pk, array):
    if pk is None:
        return None
    else:
        b = util.array_to_bytes(array)
        return Box(sk, pk).encrypt(b)


def decrypt_array(sk, pk, n, ct):
    if pk is None or ct is None:
        return np.zeros(n)
    else:
        m = Box(sk, pk).decrypt(ct)
        array = util.bytes_to_array(m)
        return array


def make_A(vec_size, n, GF, seed):
    return GF.Random((vec_size, n), seed=seed)


def color_groups(missing, group_sizes, threshold):
    def find_max(to_process):
        max_so_far = None
        for i in to_process:
            if max_so_far is None or len(missing[i]) > len(missing[max_so_far]):
                max_so_far = i
        return max_so_far

    def find_min2(to_process, missing_set):
        min_so_far = None
        current_missing = len(missing_set)

        for i in to_process:
            if min_so_far is None or len(missing_set.union(missing[i])) < current_missing:
                min_so_far = i
                current_missing = len(missing_set.union(missing[min_so_far]))
        return min_so_far

    to_process = list(missing.keys())

    groups = []
    missing_sets = []

    while to_process != []:
        # start the group using the remaining vector with largest missing set
        next_r = find_max(to_process)
        to_process.remove(next_r)
        missing_set = missing[next_r]
        group = {next_r}

        while group_sizes[next_r] - len(missing_set) > threshold:
            # add vectors that enlarge the missing set minimally
            next_add = find_min2(to_process, missing_set)

            if next_add is None:
                break
            else:
                to_process.remove(next_add)
                group.add(next_add)
                missing_set = missing_set.union(missing[next_add])

        groups.append(group)
        missing_sets.append(missing_set)

    return (groups, missing_sets)


def check_list_equal(a, b):
    equality_list = [e_a == e_b for e_a, e_b in zip(a, b)]
    return equality_list.count(True) == len(a)
