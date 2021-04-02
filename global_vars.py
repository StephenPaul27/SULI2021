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
if len(sys.argv)>2 and str.isdigit(sys.argv[2]):
    NUM_NODES = int(sys.argv[2])               # maximum number of nodes in system
else:
    NUM_NODES = 10
MSG_PERIOD = 10             # seconds between broadcast of powerref downstream
MSG_TIMEOUT = MSG_PERIOD/2            # lifespan of messages before they're cleared
CONSENSUS_TIMEOUT = MSG_TIMEOUT       # seconds until consensus times out
BLOCK_SIZE = 15             # size of each block of transactions to be added
SOCKET_CONNECTIONS = 100     # number of simultaneous socket connections that can be made
BLOCK_BUFFER = BLOCK_SIZE/2  # buffer to make sure transactions are ordered correctly
PROPOSE_TRIGGER = BLOCK_SIZE + BLOCK_BUFFER  # trigger size for proposing blocks
PENALTY = -10               # UtilityToken penalty for incorrect consensus
INCENTIVE = 1               # UtilityToken incentive for correct consensus
REWRITE_FILES = True        # Development boolean for writing files from scratch each time
TRAITOR_PORT = 8105         # port of traitor node for visualization

# load node connections
try:
    with open("Storage/node_connections.json", 'r') as f:
        node_conn = json.load(f)
except:
    do_nothing = True

# # Building to building map (indexed by sender -> receiver of power reference)
# network_map = {}

# read port from system arguments
if len(sys.argv)>1 and str.isdigit(sys.argv[1]):
    my_port = int(sys.argv[1])
else:
    my_port = BASE_PORT

first_node = False

my_hash = 0         # filler for global hash variable

my_pr_key = 0      # filler for global private key variable

# List of node hashes seen by this node (i.e. exclusive of itself)
node_list = []      # list of node hashes

# create dicts of node hashes mapped to their local ports
port_to_hash = {}
hash_to_port = {}

# create consensus variables used to come to consensus on blocks
consensus_array = []     # list of block hashes received
chain_dict = {}         # dict to store diff types of chains received
trans_vote_dict = {}         # dict to store diff transactions received
trans_dict = {}         # dict to store diff transactions received
consensus_id_list = []  # list to store nodes that have already voted once
response_timer_thread = None    # global variable holder for response timer thread
addblock_timer_thread = None    # global variable holder for addblock timer thread
response_timer = 0      # time since first introduction response received
addblock_timer = 0
consensus_index = -1    # index of last block agreed upon

# This node's blockchain copy
blockchain = []

# Store the transactions that
# this node sees in a list
this_nodes_transactions = []

validator_list = []

last_proposed = -1      # make sure duplicate requests aren't made
