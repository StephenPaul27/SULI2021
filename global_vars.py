"""
This file contains and initializes the global variables shared across files
"""

import hashlib as hasher
import time
from cryptography.fernet import Fernet
import sys
import json

# Constants
ENCODING = 'utf-8'          # bit encoding
BASE_PORT = 8100            # Base port for searching for nodes
BASE_HOST = "localhost"     # local host (must change code if using an IP instead i.e. with hardware)
# extract maximum number of nodes to check for from the commandline arguments
if len(sys.argv)>2 and str.isdigit(sys.argv[2]):
    NUM_NODES = int(sys.argv[2])               # maximum number of nodes in system
else:
    NUM_NODES = 10
MSG_PERIOD = 20             # seconds between broadcast of powerref downstream when not connected to lcdmpc
MSG_TIMEOUT = 1.5             # lifespan of messages before they're cleared
CONSENSUS_TIMEOUT = MSG_TIMEOUT*2       # seconds until consensus times out
BLOCK_SIZE = 100             # size of each block of transactions to be added
SOCKET_CONNECTIONS = 100    # number of simultaneous socket connections that can be made at a node
BLOCK_BUFFER = BLOCK_SIZE   # buffer of transactions to make sure they are ordered correctly when put into the blockchain
PROPOSE_TRIGGER = BLOCK_SIZE + BLOCK_BUFFER  # trigger size for proposing blocks
PENALTY = -10               # UtilityToken penalty for incorrect consensus
INCENTIVE = 1               # UtilityToken incentive for correct consensus
REWRITE_FILES = True        # Development boolean for writing files from scratch each time the program is run
TRAITOR_PORTS = []          # ports of traitor nodes
TARGET_NODES = []       # nodes targeted by the grid aggregator
NEGLECT_PROBABILITY = 0.5   # probability that the grid aggregator neglects the target node
DMPC_HORIZON = 20           # horizon in minutes used in LCDMPC
NORMAL_POWER = 70           # kW value that the building would return to if uncontrolled (comment out aggArray section to take effect)
DMPC_SIM = False             # bool for connecting with lcdmpc program
DMPC_PORT = 8099            # port used to send to lcdmpc program

if DMPC_SIM:
    node_connection_file = "node_connections_dmpc"
else:
    node_connection_file = "node_connections_linear"

# load node connections
try:
    with open(f"Storage/{node_connection_file}.json", 'r') as f:
        node_conn = json.load(f)
except:
    do_nothing = True

# read port from system arguments if the argument is there
if len(sys.argv) > 1 and str.isdigit(sys.argv[1]):
    my_port = int(sys.argv[1])
else:
    my_port = BASE_PORT

first_node = False

my_hash = 0         # filler for global hash variable

my_pr_key = 0      # filler for global private key variable

my_power = None         # record my power ref to provide in consensus
node_powers = {}        # record power refs of upstream nodes
power_consensus_dict = {}   # dictionary of lists of powers to perform consensus on
power_thread = {}       # dictionary of power reference threads

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
sense_thread = {}
consensus_index = -1    # index of last block agreed upon

# This node's blockchain copy
blockchain = []

# DMPC message counting variables
power_count = []
sense_count = []

# Store the transactions that
# this node sees in a list
this_nodes_transactions = []

validator_list = []

last_proposed = -1      # make sure duplicate requests aren't made
