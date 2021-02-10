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
MSG_PERIOD = 30             # seconds between broadcast of powerref
CONSENSUS_TIMEOUT = 5       # seconds until consensus times out

# Read encryption key from storage
f = open("CryptoKey.txt", "r")
cryptoKey = f.read()
f.close()

# load node connections
f = open("node_connections.json", 'r')
node_conn = json.loads(f.read())
f.close()

# integrate encryption key
Fkey = Fernet(cryptoKey)

# Building to building map (indexed by sender -> receiver of power reference)
network_map = {}

# create random hash to represent this node
my_hasher = hasher.sha256()
my_hasher.update(str(time.time()).encode())
my_hash = str(my_hasher.hexdigest())

# assign port from system arguments
my_port = int(sys.argv[1])

# List of node hashes seen by this node (i.e. exclusive of itself)
node_list = []      # list of node hashes

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
