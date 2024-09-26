from olympia.agent.Agent import Agent
from olympia.message.Message import Message
from olympia.util.util import log_print, get_msg_size
from nacl.public import PrivateKey
import pandas as pd
import random
#from agent.BaselineClientAgent import BaselineClientAgent
import time
from collections import defaultdict

class AggregationClient(Agent):
    def __init__(self, id, name, type, **kwargs):
        super().__init__(id, name, type, kwargs)
        # super().__init__(id, name, type, kwargs.get('random_state', None))
        self.params = kwargs.get('params', kwargs)
        self.total_computation_time = 0
        self.client_round_times = []

    def round(self, round_number, message):
        raise RuntimeError('Aggregation clients need to override the `round` method')

    def receiveMessage(self, currentTime, msg):
        super().receiveMessage(currentTime, msg)

        # add bandwidth delay
        message_bytes = get_msg_size(msg)
        bandwidth_b_per_sec = self.params['client_bandwidth'] * 125000  # convert to bytes per sec
        delay_in_sec = message_bytes / bandwidth_b_per_sec       # divide the size of the message in bytes by the bandwidth to get the delay in seconds.
        delay_in_ns = delay_in_sec * 1e9
        # print("CLIENT DELAY IN SECS: ", delay_in_sec)
        self.delay(int(delay_in_ns))

        t1 = time.time()
        output_msg = self.round(msg.body['round_number'], msg.body['body'])
        
        t2 = time.time()
        round_time = int((t2-t1)*1e9)
        self.client_round_times.append(round_time)
        self.total_computation_time += round_time
        self.delay(round_time)

        if output_msg is not None:
            self.sendMessage(msg.body['sender'], Message({"round_number" : msg.body['round_number'],
                                                          "sender" : self.id,
                                                          "body" : output_msg}))
    def generate_keys(self, signing_key = None):
        sk_u = PrivateKey.generate()
        pk_u = sk_u.public_key
        signed_pk_u = None
        if self.params['malicious']:
            signed_pk_u = signing_key.sign(pk_u._public_key)
        return sk_u, pk_u, signed_pk_u


class AggregationServer(Agent):
    def __init__(self, id, name, type, client_ids, random_state=None, **kwargs):
        super().__init__(id, name, type, random_state)
        self.params = kwargs.get('params', kwargs)
        self.clients = client_ids
        self.received_messages = defaultdict(dict)
        self.round_number = 1
        self.total_computation_time = 0
        self.server_round_times = []

    def kernelStarting(self, startTime):
        self.logEvent("START_TIME", startTime)
        super().kernelStarting(startTime)

    def kernelStopping(self):
        print("Agent {} reports total sum: {}".format(self.id, self.total))

        actual_total_dropouts = self.initial_client_count - len(self.received_messages[self.round_number - 1])
        allowed_total_dropouts = round(self.total_dropout_fraction * self.initial_client_count)

        if actual_total_dropouts <= allowed_total_dropouts:
            print("\nSuccess: Actual total dropouts {} is less than or equal to allowed total dropouts {}".format(
                actual_total_dropouts, allowed_total_dropouts))
        else:
            print("\nFailure: Actual total dropouts {} is greater than allowed total dropouts {}".format(
                actual_total_dropouts, allowed_total_dropouts))

        self.logEvent("STOP_TIME", self.currentTime)
        super().kernelStopping()

    def round(self, round_number, messages):
        raise RuntimeError('Aggregation servers need to override the `round` method')

    def next_round(self, round_number, messages):
        raise RuntimeError('Aggregation servers need to override the `next_round` method')

    def wakeup(self, currentTime):
        super().wakeup(currentTime)

        t1 = time.time()
        output_msgs = self.round(self.round_number, self.received_messages[self.round_number-1])
        t2 = time.time()
        round_time = int((t2-t1)*1e9)
        self.server_round_times.append(round_time)
        self.total_computation_time += round_time
        self.delay(round_time)

        if output_msgs is not None:
            if isinstance(output_msgs, tuple):
                #raise Exception('unsupported - please ask Joe about this')
                output_msg1, output_msg2 = output_msgs
                random_order_clients = list(output_msg1.keys())
                random.shuffle(random_order_clients)
                for client in random_order_clients:
                        self.sendMessage(client, Message({"round_number" : self.round_number,
                                                         "sender" : self.id,
                                                        "body" : (output_msg1[client], output_msg2[client])}))
            else: 
                random_order_clients = list(output_msgs.keys())
                random.shuffle(random_order_clients)
                for client in random_order_clients:
                    #print(f"Client: {client}, MSG: {output_msgs[client]}" )
                    self.sendMessage(client, Message({"round_number" : self.round_number,
                                                        "sender" : self.id,
                                                        "body" : output_msgs[client]}))
    def receiveMessage(self, currentTime, msg):
        super().receiveMessage(currentTime, msg)

        # add bandwidth delay
        message_bytes = get_msg_size(msg)
        bandwidth_b_per_sec = self.params['server_bandwidth'] * 125000  # convert to bytes per sec
        delay_in_sec = message_bytes / bandwidth_b_per_sec       # divide the size of the message in bytes by the bandwidth to get the delay in seconds.

        delay_in_ns = delay_in_sec * 1e9
        # print("DELAY IN SECS: ", delay_in_sec)
        self.delay(int(delay_in_ns))
        
        if msg.body['round_number'] == self.round_number:
            self.received_messages[self.round_number][msg.body['sender']] = msg.body['body']

        if self.next_round(self.round_number, self.received_messages[self.round_number]):
            self.round_number += 1
            self.setWakeup(currentTime)

    def succeed(self, result, dropouts):
        self.total = result
        self.total_dropouts = dropouts
        self.failure = 0
        # self.survived_clients = survived_clients

# class DropoutAggregationServer(AggregationServer):
#     def __init__(self, id, name, type, client_ids, params, random_state=None):
#         super().__init__(id, name, type, client_ids, random_state, params=params)
#         self.total_dropout_fraction = self.params['dropout_fraction']
#         self.num_rounds = self.params['num_rounds']
#         self.initial_client_count = len(client_ids)
#         self.dropout_threshold = round(
#             self.initial_client_count
#             - (self.total_dropout_fraction * self.initial_client_count / self.num_rounds)
#         )
#         self.threshold_reached = False  # flag to indicate if dropout threshold has been reached

#         print("DROPOUT FRACTION: ", self.total_dropout_fraction)
#         print("DROPOUT THRESHOLD: ", self.dropout_threshold)

#     def next_round(self, round_number, messages):
#         if self.threshold_reached:  # if threshold has been reached, prevent further dropouts
#             return True

#         if len(messages.keys()) >= self.dropout_threshold:
#             self.dropout_threshold = round(
#                 self.initial_client_count
#                 - (self.total_dropout_fraction * self.initial_client_count / self.num_rounds * (round_number + 1))
#             )
#             self.threshold_reached = True  # update the flag
#             return True
#         else:
#             return False

#     def succeed(self, result):
#         self.total_dropouts = len(self.clients) - len(self.received_messages[self.round_number-1])
#         self.total = result
#         self.survived_clients = self.received_messages[self.round_number-1].keys()
#         self.failure = 0

class DropoutAggregationServer(AggregationServer):

    def __init__(self, id, name, type, client_ids, params, random_state=None):
        super().__init__(id, name, type, client_ids, random_state, params = params)

        self.total_dropout_fraction = self.params['dropout_fraction']
        self.num_rounds = self.params['num_rounds']
        self.initial_client_count = len(client_ids)
        self.dropout_threshold = round(
            self.initial_client_count
            - (self.total_dropout_fraction * self.initial_client_count / self.num_rounds)
        )
        print("DROPOUT FRACTION: ", self.total_dropout_fraction)
        print("DROPOUT THRESHOLD: ", self.dropout_threshold)
        
    def next_round(self, round_number, messages):
        if len(messages.keys()) >= self.dropout_threshold:
            self.dropout_threshold = round(
                self.initial_client_count
                - (self.total_dropout_fraction * self.initial_client_count / self.num_rounds * (round_number + 1))
            )
            return True
        else:
            return False

    def succeed(self, result):
        self.total_dropouts = len(self.clients) - len(self.received_messages[self.round_number-1])
        self.total = result
        self.survived_clients = self.received_messages[self.round_number-1].keys()
        self.failure = 0
