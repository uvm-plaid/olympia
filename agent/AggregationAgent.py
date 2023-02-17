from agent.Agent import Agent
from message.Message import Message
from util.util import log_print
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

    def round(self, round_number, message):
        raise RuntimeError('Aggregation clients need to override the `round` method')

    def receiveMessage(self, currentTime, msg):
        super().receiveMessage(currentTime, msg)

        t1 = time.time()
        output_msg = self.round(msg.body['round_number'], msg.body['body'])
        
        t2 = time.time()
        ct = int((t2-t1)*1e9)
        self.total_computation_time += ct
        self.delay(ct)

        if output_msg is not None:
            self.sendMessage(msg.body['sender'], Message({"round_number" : msg.body['round_number'],
                                                          "sender" : self.id,
                                                          "body" : output_msg}))

class AggregationServer(Agent):
    def __init__(self, id, name, type, client_ids, random_state=None, **kwargs):
        super().__init__(id, name, type, random_state)
        self.params = kwargs.get('params', kwargs)
        self.clients = client_ids
        self.received_messages = defaultdict(dict)
        self.round_number = 1
        self.total_computation_time = 0

    def kernelStarting(self, startTime):
        self.logEvent("START_TIME", startTime)
        super().kernelStarting(startTime)

    def kernelStopping(self):
        print("Agent {} reports total sum: {}".format(self.id, self.total))

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
        ct = int((t2-t1)*1e9)
        self.total_computation_time += ct
        self.delay(ct)

        if output_msgs is not None:
            if isinstance(output_msgs, tuple):
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
        
        if msg.body['round_number'] == self.round_number:
            self.received_messages[self.round_number][msg.body['sender']] = msg.body['body']

        if self.next_round(self.round_number, self.received_messages[self.round_number]):
            self.round_number += 1
            self.setWakeup(currentTime)

    def succeed(self, result, dropouts):
        self.total = result
        self.total_dropouts = dropouts
        self.failure = 0

class DropoutAggregationServer(AggregationServer):
    dropout_fraction = 0.0

    def __init__(self, id, name, type, client_ids, params, random_state=None):
        super().__init__(id, name, type, client_ids, random_state, params = params)
        self.dropout_threshold = len(client_ids) - self.dropout_fraction * len(client_ids)

        # self.server_class(0, f"{self.protocol_name} Service Agent 0", 
        #                     f"{self.protocol_name}ServiceAgent",
        #                         client_ids,
        #                         params = self.params,
        #                         random_state = server_random_state)

    def next_round(self, round_number, messages):
        if len(messages.keys()) >= self.dropout_threshold:
            self.dropout_threshold = self.dropout_threshold - \
              (self.dropout_threshold * self.dropout_fraction)
            #print('dropout threshold becomes:', self.dropout_threshold)
            #print(self.dropout_threshold * self.dropout_fraction)
            return True
        else:
            return False

    def succeed(self, result):
        self.total_dropouts = len(self.clients) - len(self.received_messages[self.round_number-1])
        self.total = result
        self.failure = 0
