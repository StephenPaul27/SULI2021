"""
Blockchain Network Code
Stephen Paul

format: python <filename>.py <port>

This program will create a node to be used in a blockchain-like network.
Nodes will communicate with each other via P2P where each node is both server and client.
The goal is to attain stability when <=1/3rd of nodes provide faulty information
"""

import socket
import threading
import sys
import time
import json
import hashlib as hasher
import datetime as date

ENCODING = 'utf-8'
BASE_PORT = 8080            # Base port for searching for nodes
BASE_HOST = "localhost"     # local host (must change code if using an IP instead)
NUM_NODES = 3      # maximum number of nodes in system
MSG_PERIOD = 60     # seconds between broadcast of powerref
CONSENSUS_TIMEOUT = 5 # seconds until consensus times out

# create random hash to represent this node
my_hasher = hasher.sha256()
my_hasher.update(str(time.time()).encode())
my_hash = str(my_hasher.hexdigest())

# List of node hashes seen by this node (i.e. exclusive of itself)
node_list = []

# create dicts of node hashes mapped to their local ports
port_to_hash = {}
hash_to_port = {}

# create consensus variables used to come to consensus on blocks
consensus_dict = {}     # dict/histogram of block hashes received
chain_dict = {}         # dict to store diff types of chains received
consensus_time = 0      # time since first response received
consensus_index = -1    # index of last block agreed upon
consensus_count = 0     # count of consensus messages received

# This node's blockchain copy
blockchain = []
# Store the transactions that
# this node sees in a list
this_nodes_transactions = []

######### BLOCKCHAIN CODE ##################

# Define what a block is
class Block:

    # block structure
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.hash_block()

    # Create a hash for the block
    def hash_block(self):
        sha = hasher.sha256()
        sha.update((str(self.index) + str(self.timestamp) + str(self.data) + str(self.previous_hash)).encode())
        return sha.hexdigest()

# return list of blocks in this node's blockchain
def get_blocks():

    chain_to_send = blockchain
    # Convert our blocks into dictionaries
    # so we can send them as json objects later
    for i in range(len(chain_to_send)):
        block = chain_to_send[i]
        block_index = block.index
        block_timestamp = str(block.timestamp)
        block_data = str(block.data)
        block_hash = block.hash
        block_prevhash = block.previous_hash
        chain_to_send[i] = {
            "index": block_index,
            "timestamp": block_timestamp,
            "data": block_data,
            "previous_hash": block_prevhash,
            "hash": block_hash
        }
    chain_to_send = json.dumps(chain_to_send)
    return chain_to_send

"""
This function creates the genesis block upon this node's instantiation.
This is only relevant if it is the first node in the system, as all other nodes will
seek consensus and throw away their genesis block
"""
def create_genesis_block():
    # Manually construct a block with
    # index zero and arbitrary previous hash
    return Block(0, date.datetime.now(), {
        "proof-of-work": 100,
        "transactions": None
    }, "0")

"""
This function is responsible for enacting consensus on this node's blockchain.
Once all "votes" have been received or the time window has expired, the most popular
"vote" is copied to our blockchain if it is agreed upon by >50% of the nodes
"""
def consensus():
    global consensus_index
    global consensus_count
    global consensus_dict
    global chain_dict
    global blockchain
    # sort consensus dict by quantity of nodes agreeing on a hash
    sorted_consensus = sorted(consensus_dict, key=lambda k: len(consensus_dict[k]), reverse=True)

    # If most popular choice has > than half of all nodes agreeing, go with that choice
    if len(consensus_dict[sorted_consensus[0]]) > (len(node_list))/2:
        # erase own blockchain if it hasn't performed consensus yet
        if consensus_index == -1:
            blockchain = []
        # add each block to our blockchain that is past what we've already agreed on
        for i in chain_dict[sorted_consensus[0]]:
            if i['index'] > consensus_index:
                blockchain.append(Block(i['index'], i['timestamp'], i['data'], i['previous_hash']))
                consensus_index = i['index']
    consensus_count = 0
    consensus_dict = {}
    chain_dict = {}
    print(f"Consensus performed, resulting chain: {blockchain}")


# validate a chain against its given hash
def validate(chain, lasthash):
    print("Validating...")
    # initialize the hash
    sha = hasher.sha256()
    sha.update((str(chain[0]['index']) + str(chain[0]['timestamp']) + str(chain[0]['data']) + str(chain[0]['previous_hash'])).encode())
    # check validity of provided blockchain (for every block after the first)
    if len(chain) > 1:
        for i in range(0, len(chain)-1):
            sha.update((str(chain[i]['index']) + str(chain[i]['timestamp']) + str(chain[i]['data']) + str(chain[i]['previous_hash'])).encode())
            if sha.hexdigest() != chain[i + 1]['previous_hash'] or sha.hexdigest() != chain[i]['hash']:
                print("False- bad chain")
                return False

    # check final hash against provided hash
    # also check that the provided blockchain is longer than what we've agreed on already
    if lasthash != sha.hexdigest() or (consensus_index >= chain[-1]['index']):
        print("False bad hash/index")
        breakpoint()
        return False

    print("True")
    return True

######### COMMUNICATION CODE #####################

# Server to receive incoming transmissions
class Receiver(threading.Thread):

    def __init__(self, my_host, my_port):
        threading.Thread.__init__(self, name="messenger_receiver")
        self.host = my_host
        self.port = my_port

    def listen(self):

        # create server socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(NUM_NODES)
        # print("server started")
        # while loop to accept incoming connections/messages
        while True:

            # accept client connection
            connection, client_address = sock.accept()
            # print(connection)

            try:
                full_message = ""

                # while loop to read in data from incoming message
                while True:

                    data = connection.recv(1024)
                    full_message = full_message + data.decode(ENCODING)
                    # print(data.decode(ENCODING))
                    # once data has stopped coming in, decode the message
                    if not data:
                        # print("received a message")
                        try:
                            # load the message structure
                            msgJson = json.loads(full_message)

                            # load the data structure that the message is carrying
                            msgData = json.loads(msgJson['data'])
                            # print("msgJson", msgJson)

                            # action upon handshake
                            if msgJson['type'] == "intro" or msgJson['type'] == "response":

                                # map sender's hash to its local port
                                port_to_hash[msgData['fromport']] = msgJson['from']
                                hash_to_port[msgJson['from']] = msgData['fromport']

                                # append new node to list of nodes
                                if msgJson['from'] not in node_list:
                                    node_list.append(msgJson['from'])
                                    #print(f"node list: {node_list}")

                                print(f"received handshake from {msgJson['data']}")

                            # Response algorithm
                            if (msgJson['type'] == "intro" or msgJson['type'] == "request") \
                                    and msgJson['to'] == self.port:

                                # respond with port and blockchain for consensus
                                try:
                                    message = {
                                        "type": "response",
                                        "from": my_hash,
                                        "to": msgJson['from'],
                                        "time": time.time()
                                    }
                                    if msgJson['type'] == "intro":
                                        message['data'] = json.dumps({"fromport": self.port,
                                              "lasthash": blockchain[-1].hash, "chain": get_blocks()})
                                    else:
                                        message['data'] = json.dumps({"lasthash": blockchain[-1].hash,
                                                                      "chain": get_blocks()})
                                    sendMessage(json.dumps(message), int(msgData['fromport']))
                                except Exception as e:
                                    print("could not respond to introduction because ", e)

                                # reaction to response
                            elif msgJson['type'] == "response":
                                global consensus_dict
                                global consensus_time
                                global consensus_count
                                global chain_dict
                                loaded_chain = json.loads(msgData['chain'])
                                # recognize consensus only on NEW blocks

                                if loaded_chain[-1]['index'] > consensus_index:

                                    consensus_count += 1    #increment number of consensus messages received

                                    # Histogram the votes for the blockchain hash
                                    if msgData['lasthash'] in consensus_dict:
                                        consensus_dict[msgData['lasthash']].append(msgJson['from'])
                                    # if not in the histogram yet, add them after validating the chain
                                    elif validate(loaded_chain, msgData['lasthash']):
                                        # store the chain itself
                                        chain_dict[msgData['lasthash']] = loaded_chain
                                        # add to histogram
                                        consensus_dict[msgData['lasthash']] = [msgJson['from']]

                                    # if consensus has timed out or received messages from all nodes
                                    if consensus_time and (time.time() - consensus_time > CONSENSUS_TIMEOUT) \
                                            or consensus_count == len(node_list):
                                        consensus()
                                    elif not consensus_time:
                                        # Start recording time since consensus began
                                        consensus_time = time.time()

                            # reaction to power ref transmission
                            elif msgJson['type'] == "powerref":
                                print(f"type: {msgJson['type']}\n"
                                      f"from: {msgJson['from']}\n"
                                      f"to: {msgJson['to']}\n"
                                      f"data: {msgJson['data']}\n"
                                      f"time: {msgJson['time']}\n")
                        # Exception catch from message conversion to json
                        except Exception as e:
                            print(f"Error decoding received message: {e}")
                        break
            finally:
                #connection.shutdown(2)
                connection.close()

    def run(self):
        self.listen()


"""
This class is responsible for actively sending data including power references and introduction
"""
class Sender(threading.Thread):

    def __init__(self, my_host, my_port):
        threading.Thread.__init__(self, name="messenger_sender")
        # self.host = my_friends_host
        # self.port = my_friends_port
        self.my_host = my_host
        self.my_port = my_port

    def run(self):

        # Introduce yourself on the first run
        for i in range(0, NUM_NODES):  # broadcast to connected clients from 8080 to 80XX
            if BASE_PORT + i != self.my_port:   # don't send to yourself
                try:
                    # send my hash to all existing nodes
                    message = json.dumps({
                        "type": "intro",
                        "from": my_hash,
                        "to": BASE_PORT + i,
                        "data": json.dumps({"fromport": self.my_port}),
                        "time": time.time()
                    })
                    sendMessage(message, BASE_PORT + i)
                except Exception as e:
                    print(f"no connection at {BASE_PORT+i}")

        while True:
            time.sleep(MSG_PERIOD)      # sleep X seconds before each broadcast
            # print(f"node list: {node_list}")
            for i in node_list:   # broadcast to connected clients in node list
                if(hash_to_port[i] != self.my_port):
                    try:
                        message = json.dumps({
                            "type": "powerref",
                            "from": my_hash,
                            "to": i,
                            "data": 32.56,
                            "time": time.time()
                        })
                        sendMessage(message, hash_to_port[i])
                    except Exception as e:
                        do_nothing = True

def sendMessage(message,destPort):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((BASE_HOST, destPort))

    s.sendall(str(message).encode(ENCODING))

    # s.shutdown(2)
    s.close()

def main():
    blockchain.append(create_genesis_block())
    print(f"Genesis block: {blockchain[0].hash}")
    # my_host = "localhost"
    #my_host = input("which is my host? ")
    my_port = int(sys.argv[1])
    port_to_hash[my_port] = my_hash
    # print(node_list)
    #my_port = int(input("which is my port? "))
    receiver = Receiver(BASE_HOST, my_port)
    # my_friends_host = input("what is your friend's host? ")
    # my_friends_port = int(input("what is your friend's port?"))
    sender = Sender(BASE_HOST, my_port)
    threads = [receiver.start(), sender.start()]

if __name__ == '__main__':
    main()