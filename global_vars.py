"""
This file contains and initializes the global variables shared across files
"""

import hashlib as hasher
import time
from cryptography.fernet import Fernet
import sys
import json

# Constants
ENCODING = 'utf-8'
BASE_PORT = 8080            # Base port for searching for nodes
BASE_HOST = "localhost"     # local host (must change code if using an IP instead)
NUM_NODES = 5               # maximum number of nodes in system
MSG_PERIOD = 30             # seconds between broadcast of powerref downstream
MSG_TIMEOUT = 10            # lifespan of messages before they're cleared
CONSENSUS_TIMEOUT = 5       # seconds until consensus times out
BLOCK_SIZE = 10             # size of each block of transactions to be added

# Read encryption key from storage
with open("Storage/CryptoKey.txt", "r") as f:
    cryptoKey = f.read()

# load node connections
with open("Storage/node_connections.json", 'r') as f:
    node_conn = json.loads(f.read())

# integrate encryption key
Fkey = Fernet(cryptoKey)

# Building to building map (indexed by sender -> receiver of power reference)
network_map = {}

# read port from system arguments
my_port = int(sys.argv[1])

my_hash = 0         # filler for global hash variable

my_pr_key = 0      # filler for global private key variable

# List of node hashes seen by this node (i.e. exclusive of itself)
node_list = []      # list of node hashes

# create dicts of node hashes mapped to their local ports
port_to_hash = {}
hash_to_port = {}

# create map of hash to unique identifier
identifier_dict = {}

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

# dictionary to track transmission of messages
# indexed by a random message hash id
transaction_tracking = {}