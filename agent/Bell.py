from agent.AggregationAgent import AggregationClient, DropoutAggregationServer
from nacl.public import PrivateKey, Box
import util.simple_sharing as shamir
import util.shamir_sharing as shamir
from util import util
from collections import defaultdict, OrderedDict
import numpy as np
import networkx as nx
from networkx.generators.harary_graph import *

class BellClientAgent(AggregationClient):
    def round(self, round_number, message):
        self.GF = self.params['gf']
        self.random_state = self.params['random_state']
        self.add_mask = 0
        self.subtract_mask = 0

        if round_number == 1:                   # generate keys
            self.neighbor_list  = message
            self.sk1_u = PrivateKey.generate() 
            self.pk1_u = self.sk1_u.public_key
            self.b_u =  self.random_state.randint(low = 1, high = 100) #personal mask seed 

            self.sk2_u = PrivateKey.generate() 
            self.pk2_u = self.sk2_u.public_key
       
            return {'pk1': self.pk1_u, 'pk2': self.pk2_u}

        elif round_number == 2:                 # generate encrypted secret shares
            self.neighbor_pks1_with_dropouts, self.neighbor_pks2_with_dropouts = message
            
            # without dropped out neighbors
            self.neighbor_pks1 = {k: v for k, v in self.neighbor_pks1_with_dropouts.items() if v is not None}
            self.neighbor_pks2  = {k: v for k, v in self.neighbor_pks2_with_dropouts.items() if v is not None}

            n_range = list(sorted(self.neighbor_pks2.keys()))

            self.b_u_shares = shamir.share_array(self.GF([self.b_u]), n_range, len(n_range)//2, self.GF)
            self.sk_u_shares = shamir.share_array(util.bytes_to_field_array(self.sk1_u._private_key, self.GF), n_range, len(n_range)//2, self.GF)
            
            enc_bu_share = {c: self.b_u_shares[c].encrypt(self.sk2_u, pk)
                          for c, pk in self.neighbor_pks2.items()
                          if c in self.b_u_shares}

            enc_sku_share = {c: self.sk_u_shares[c].encrypt(self.sk2_u, pk)
                          for c, pk in self.neighbor_pks2.items()
                          if c in self.sk_u_shares}

            return {'enc_bu_share': enc_bu_share, 'enc_sku_share': enc_sku_share} 
        
        elif round_number == 3:                 # Submit masked values
            client_value = self.GF(self.random_state.randint(low = 0, high = 100,
                                                           size=self.params['dim']))
            self.enc_bu_shares, self.enc_sku_shares = message

            # Update pks i.e remove any keys dropped out in previous round 
            dropped_out_pk = list(set(self.neighbor_pks2.keys()) - set(self.enc_bu_shares.keys()))
            for pk in dropped_out_pk:
                del self.neighbor_pks1[pk]
                del self.neighbor_pks2[pk]
            
            for agent_id, pk_v in self.neighbor_pks1.items():
                # Add vector with seed s_uv
                shared_key_box = Box(self.sk1_u, pk_v)
                s_uv = abs(hash31(shared_key_box.shared_key()))   
                np.random.seed(s_uv) 
                mask_array = np.random.randint(low = 0, high = 100, size=self.params['dim']) 

                if self.id > agent_id:
                    self.add_mask += mask_array  
                elif self.id < agent_id: 
                    self.subtract_mask += mask_array

            # Add vector with seed b_u
            np.random.seed(self.b_u) 
            self.p_u = np.random.randint(low = 0, high = 100, size=self.params['dim'])
            masked_value = client_value + self.GF(self.add_mask) - self.GF(self.subtract_mask) + self.GF(self.p_u)

            return masked_value

        elif round_number == 4:                 # sum up the received shares
            non_dropout_list = message 

            dec_bu_share = { c: s.decrypt(self.sk2_u, self.neighbor_pks2[c])
                          for c, s in self.enc_bu_shares.items()
                          if c in self.neighbor_pks2}

            dec_sku_share = { c: s.decrypt(self.sk2_u, self.neighbor_pks2[c])
                          for c, s in self.enc_sku_shares.items()
                          if c in self.neighbor_pks2}

            # U2 \ U3
            dropout_list = list(set(dec_bu_share.keys()) - set(non_dropout_list))

            # Filter bu and sku values to send to server
            bu_share = { k: dec_bu_share[k] if k in non_dropout_list else shamir.ArrayShare(dec_bu_share[k].x, np.array([0]), dec_bu_share[k].T, dec_bu_share[k].GF) \
                        for k in self.neighbor_pks2.keys() }
            sku_share = { k: dec_sku_share[k] if k in dropout_list else shamir.ArrayShare(dec_sku_share[k].x, np.array([0]), dec_sku_share[k].T, dec_sku_share[k].GF) \
                         for k in self.neighbor_pks2.keys()}

            return {'bu_share': bu_share, 'sku_share': sku_share, 'dropout_list': dropout_list}

class BellServiceAgent(DropoutAggregationServer):
    dropout_fraction = 0.05
   
    def round(self, round_number, messages):
        self.GF = self.params['gf']
        self.num_clients = self.params['num_clients']
        add_p_vu = 0
        subtract_p_vu = 0 

        # # Set k parameter
        if self.num_clients <= 50:
            k_node_connectivity = self.num_clients-1
        else:
            k_node_connectivity = 50

        if round_number == 1:                          # start the protocol
            self.all_neighbor_list = {}
            # Generate graph and send each client its neighbors
            net = hkn_harary_graph(k_node_connectivity, len(self.clients))

            # how do we access the clients that have dropped out from here?
            # So, that we can send info to the right neighbors
            for c in self.clients:   
                neighbors = list(net.edges(c-1)) 
                neighbor_list = [sub[1]+1 for sub in neighbors] 

                self.all_neighbor_list[c] = neighbor_list
            return self.all_neighbor_list 

        elif round_number == 2:           # broadcast received public keys
            self.pks1 = {}
            self.pks2 = {}
            self.neighbor_pks1_src, self.neighbor_pks2_src = {}, {}
            for k, v in messages.items():
                self.pks1[k] = v['pk1']
                self.pks2[k] = v['pk2']

            self.u1 = list(sorted(self.pks1.keys()))

            for c, pk1 in self.pks1.items():
                self.neighbor_pks1, self.neighbor_pks2 = {}, {}
                neigbors = self.all_neighbor_list.get(c)
                for neigbor in neigbors: 
                    self.neighbor_pks1[neigbor] = self.pks1.get(neigbor)
                    self.neighbor_pks2[neigbor] = self.pks2.get(neigbor)

                self.neighbor_pks1_src[c] =  self.neighbor_pks1
                self.neighbor_pks2_src[c] =  self.neighbor_pks2
            return (self.neighbor_pks1_src, self.neighbor_pks2_src)

        elif round_number == 3:                        # route shares to destination clients
            bu_out_shares = defaultdict(dict)
            sku_out_shares = defaultdict(dict)
            enc_bu_shares, enc_sku_shares = {}, {}
            for k, v in messages.items():
                enc_bu_shares[k] = v['enc_bu_share']
                enc_sku_shares[k] = v['enc_sku_share']

            self.u2 = list(sorted(enc_bu_shares.keys())) 

            for source in enc_bu_shares.keys():
                for dest in enc_bu_shares[source].keys():
                    bu_out_shares[dest][source] = enc_bu_shares[source][dest] 
                
                for dest in enc_sku_shares[source].keys():
                    sku_out_shares[dest][source] = enc_sku_shares[source][dest]
                        
            return (bu_out_shares, sku_out_shares)

        elif round_number == 4:                        # process dropouts from masked_vals
            non_dropout_dict = defaultdict(dict)
            self.u3 = list(sorted(messages.keys()))
            non_dropout_list = list(messages.keys())
            for k in messages.keys():
                non_dropout_dict[k] = non_dropout_list 

            self.masked_values = messages
            return non_dropout_dict

        elif round_number == 5:                        # reconstruct sum from received shares
            array = self.GF(list(self.masked_values.values()))
            self.total = array.sum(axis=0)
            
            received_bu_shares = {}
            received_sku_shares = {}

            final_bu_shares = {} 
            final_sku_shares = {} 
            bu_reconstructed = []
            sk_u_reconstructed = {} 
            for k, v in messages.items():
                received_bu_shares[k]=v['bu_share']
                received_sku_shares[k]=v['sku_share']
                dropout_list=v['dropout_list']

            # remove private mask (bu)
            final_bu_shares = {key:[] for key in range(1, len(self.clients)+1)}   
            for agent, shares in(received_bu_shares.items()):
                for k, v in shares.items():
                    final_bu_shares[k].append(v)
            for k, v in final_bu_shares.items():
                if k not in dropout_list and len(v)>0:
                    bu_reconstructed.append(shamir.reconstruct_array(v)[0])

            for i in bu_reconstructed:
                if i != 0:
                    np.random.seed(i.tolist())
                    p_u = np.random.randint(low = 0, high = 100, size=self.params['dim'])
                    self.total = self.total - self.GF(p_u)

            # remove pair-wise mask (sku)
            final_sku_shares = {key:[] for key in range(1, len(self.clients)+1)}   
            for agent, shares in(received_sku_shares.items()):
                for k, v in shares.items():
                    final_sku_shares[k].append(v)
            for k, v in final_sku_shares.items():
                if k in dropout_list and len(v)>0:
                    sk_u_reconstructed[k] = shamir.reconstruct_array(v)

            for key, sku_value in sk_u_reconstructed.items():
                sk_u = util.field_array_to_bytes(sku_value, 32, self.GF)
                for agent_id in self.u3:
                  pk_v = self.pks1[agent_id]
                  shared_key_box = Box(PrivateKey(sk_u), pk_v) 
                  s_uv = abs(hash31(shared_key_box.shared_key())) 
                  np.random.seed(s_uv) 
                  p_vu = np.random.randint(low = 0, high = 100, size=self.params['dim'])

                  if key > agent_id:
                      add_p_vu += p_vu
                  elif key < agent_id: 
                      subtract_p_vu += p_vu

            self.total = self.total + self.GF(add_p_vu) - self.GF(subtract_p_vu)
            self.succeed(result   =  self.total)
            
           
#31bit hash function
def hash31(value):
  return hash(value) & (2**31-1)
