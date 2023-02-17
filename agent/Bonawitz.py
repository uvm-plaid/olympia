from agent.AggregationAgent import AggregationClient, DropoutAggregationServer
from nacl.public import PrivateKey, Box
import util.simple_sharing as shamir
import util.shamir_sharing as shamir

from util import util
from collections import defaultdict
import numpy as np

class BonawitzClientAgent(AggregationClient):
    def round(self, round_number, message):
        self.GF = self.params['gf']
        self.random_state = self.params['random_state']
        self.add_mask = 0
        self.subtract_mask = 0

        if round_number == 1:                   # generate keys
            self.sk_u = PrivateKey.generate()
            self.pk_u = self.sk_u.public_key
            self.b_u =  self.random_state.randint(low = 1, high = 100) #personal mask seed 

            return self.pk_u

        elif round_number == 2:                 # generate encrypted secret shares
            self.pks = message
            n_range = list(sorted(self.pks.keys()))
            self.b_u_shares = shamir.share_array(self.GF([self.b_u]), n_range, len(n_range)//2, self.GF)
            self.sk_u_shares = shamir.share_array(util.bytes_to_field_array(self.sk_u._private_key, self.GF), n_range, len(n_range)//2, self.GF)
    
            enc_bu_share = {c: self.b_u_shares[c].encrypt(self.sk_u, pk)
                          for c, pk in self.pks.items()
                          if c in self.b_u_shares}

            enc_sku_share = {c: self.sk_u_shares[c].encrypt(self.sk_u, pk)
                          for c, pk in self.pks.items()
                          if c in self.sk_u_shares}

            return {'enc_bu_share': enc_bu_share, 'enc_sku_share': enc_sku_share}
            
        
        elif round_number == 3:                 # Submit masked values
            client_value = self.GF(self.random_state.randint(low = 0, high = 100,
                                                           size=self.params['dim']))
            self.enc_bu_shares, self.enc_sku_shares = message

            # Update pks i.e remove any keys dropped out in previous round 
            dropped_out_pk = list(set(self.pks.keys()) - set(self.enc_bu_shares.keys()))
            for pk in dropped_out_pk:
                del self.pks[pk]

            for agent_id, pk_v in self.pks.items():
              shared_key_box = Box(self.sk_u, pk_v)
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

        elif round_number == 4:                # sum up the received shares
            non_dropout_list = message
            dec_bu_share = { c: s.decrypt(self.sk_u, self.pks[c])
                          for c, s in self.enc_bu_shares.items()
                          if c in self.pks}

            dec_sku_share = { c: s.decrypt(self.sk_u, self.pks[c])
                          for c, s in self.enc_sku_shares.items()
                          if c in self.pks}

            # U2 \ U3
            dropout_list = list(set(dec_bu_share.keys()) - set(non_dropout_list))

            # Filter bu and sku values to send to server
            bu_share = { k: dec_bu_share[k] if k in non_dropout_list else shamir.ArrayShare(dec_bu_share[k].x, np.array([0]), dec_bu_share[k].T, dec_bu_share[k].GF) \
                        for k in self.pks.keys() }
            sku_share = { k: dec_sku_share[k] if k in dropout_list else shamir.ArrayShare(dec_sku_share[k].x, np.array([0]), dec_sku_share[k].T, dec_sku_share[k].GF) \
                         for k in self.pks.keys()}

            return {'bu_share': bu_share, 'sku_share': sku_share, 'dropout_list': dropout_list}
            


class BonawitzServiceAgent(DropoutAggregationServer):
    dropout_fraction = 0.05
    def round(self, round_number, messages):
        self.GF = self.params['gf']
        add_p_vu = 0
        subtract_p_vu = 0

        if round_number == 1:                          # start the protocol
            return {client: None for client in self.clients}

        elif round_number == 2:
            pks = messages
            self.all_pks = {client: pks for client in pks.keys()}
            self.u1 = list(sorted(self.all_pks.keys()))
            return self.all_pks

        elif round_number == 3:                        # route shares to destination clients
            bu_out_shares = defaultdict(dict)
            sku_out_shares = defaultdict(dict)
            enc_bu_shares, enc_sku_shares = {}, {}
            for k, v in messages.items():
                enc_bu_shares[k] = v['enc_bu_share']
                enc_sku_shares[k] = v['enc_sku_share']

            self.u2 = list(sorted(messages.keys()))

            # for source in messages.keys():
            for source in enc_bu_shares.keys():
                for dest in enc_bu_shares.keys():
                    bu_out_shares[dest][source] = enc_bu_shares[source][dest] 
                
                for dest in enc_sku_shares.keys():
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
                  pk_v = list(self.all_pks.values())[0][agent_id]
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
