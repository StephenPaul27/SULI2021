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
BASE_PORT = 8100            # Base port for searching for nodes
BASE_HOST = "localhost"     # local host (must change code if using an IP instead)
NUM_NODES = 5               # maximum number of nodes in system
MSG_PERIOD = 5             # seconds between broadcast of powerref downstream
MSG_TIMEOUT = 5            # lifespan of messages before they're cleared
CONSENSUS_TIMEOUT = 5       # seconds until consensus times out
BLOCK_SIZE = 10             # size of each block of transactions to be added
PENALTY = -10               # UtilityToken penalty for incorrect consensus
INCENTIVE = 1               # UtilityToken incentive for correct consensus
REWRITE_FILES = True        # Development boolean for writing files from scratch each time

# load node connections
try:
    with open("Storage/node_connections.json", 'r') as f:
        node_conn = json.load(f)
except:
    do_nothing = True

# # Building to building map (indexed by sender -> receiver of power reference)
# network_map = {}

# read port from system arguments
if str.isdigit(sys.argv[1]):
    my_port = int(sys.argv[1])
else:
    my_port = BASE_PORT

my_hash = 0         # filler for global hash variable

my_pr_key = 0      # filler for global private key variable

# List of node hashes seen by this node (i.e. exclusive of itself)
node_list = []      # list of node hashes

# create dicts of node hashes mapped to their local ports
port_to_hash = {}
hash_to_port = {}

# create consensus variables used to come to consensus on blocks
consensus_dict = {}     # dict/histogram of block hashes received
chain_dict = {}         # dict to store diff types of chains received
trans_dict = {}         # dict to store diff transactions received
consensus_id_list = []  # list to store nodes that have already voted once
consensus_time = 0      # time since first response received
consensus_index = -1    # index of last block agreed upon

# This node's blockchain copy
blockchain = []

# Store the transactions that
# this node sees in a list
this_nodes_transactions = []

# dictionary to track transmission of messages
# indexed by a random message hash id
transaction_tracking = {}

validator_list = []