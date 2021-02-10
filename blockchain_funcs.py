"""
This file contains functions and classes related to the blockchain
This includes the general structure, consensus, validation
"""

# imports
from all_imports import *

######### BLOCKCHAIN CODE ##################


"""
This class defines the structure of a block
"""
class Block:

    # block structure
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.hash_block()

    """
    This function returns the hash of the local block, using the index, timestamp, data, and previous hash
    """
    def hash_block(self):
        sha = hasher.sha256()
        sha.update((str(self.index) + str(self.timestamp) + str(self.data) + str(self.previous_hash)).encode())
        return sha.hexdigest()

"""
This function returns a json-string of blocks in this node's blockchain 
"""
def get_blocks():
    global blockchain
    # chain_to_send = blockchain
    chain_to_send = []
    # Convert our blocks into dictionaries
    # so we can send them as json objects later
    for i in range(len(blockchain)):
        block = blockchain[i]
        block_index = block.index
        block_timestamp = str(block.timestamp)
        block_data = str(block.data)
        block_hash = block.hash
        block_prevhash = block.previous_hash
        chain_to_send.append({
            "index": block_index,
            "timestamp": block_timestamp,
            "data": block_data,
            "previous_hash": block_prevhash,
            "hash": block_hash
        })
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
    global consensus_time
    global chain_dict
    global blockchain
    global node_list

    # sort consensus dict by quantity of nodes agreeing on a hash
    sorted_consensus = sorted(consensus_dict, key=lambda k: len(consensus_dict[k]), reverse=True)

    # debugging
    # print(f"before consensus performed, chain: {blockchain[-1].hash}")
    # print(f"consensus_time: {consensus_time}")
    # print(f"consensus_dict: {consensus_dict}")
    # print(f"sorted_consensus: {sorted_consensus}")

    # If most popular choice has > than half of all nodes agreeing, go with that choice
    if len(consensus_dict[sorted_consensus[0]]) > (len(node_list))/2:

        # erase any blocks in our chain that have not been agreed on
        while len(blockchain) and blockchain[-1].index > consensus_index:
            blockchain.pop(len(blockchain)-1)

        # add each block to our blockchain that is past what we've already agreed on
        for i in chain_dict[sorted_consensus[0]]:
            if i['index'] > consensus_index:
                blockchain.append(Block(i['index'], i['timestamp'], i['data'], i['previous_hash']))
                consensus_index = i['index']
    else:
        logging.warning(f"consensus error: popular choice <= half of all nodes, at port {my_port}")

    # Reset consensus variables
    consensus_count = 0
    consensus_dict = {}
    consensus_time = 0
    chain_dict = {}

    print(f"Consensus performed, resulting chain: {blockchain[-1].hash}")


"""
This function validates a chain against itself and its claimed hash
"""
def validate(chain, lasthash):
    print("Validating:", lasthash)
    # initialize the hash
    sha = hasher.sha256()
    sha.update((str(chain[0]['index']) + str(chain[0]['timestamp']) + str(chain[0]['data']) + str(chain[0]['previous_hash'])).encode())

    # check validity of provided blockchain (for every block after the first)
    if len(chain) > 1:
        for i in range(0, len(chain)-1):
            # reproduce the hash from the data in each block
            sha.update((str(chain[i]['index']) + str(chain[i]['timestamp']) + str(chain[i]['data']) + str(chain[i]['previous_hash'])).encode())
            # if fail to reproduce the same hash as the current block,
            # as well as the 'previous hash' of the next block, then blockchain is invalid
            if sha.hexdigest() != chain[i + 1]['previous_hash'] or sha.hexdigest() != chain[i]['hash']:
                print("Failed: bad chain")
                logging.warning(f"chain of {lasthash} was invalid ")
                return False

    # check final hash against provided hash
    # also check that the provided blockchain is longer than what we've agreed on already
    if lasthash != sha.hexdigest() or (consensus_index >= chain[-1]['index']):
        print("Failed: bad hash/index")
        logging.warning(f"{lasthash} did not match it chain or was not long enough")
        return False

    # If nothing failed, then the chain is valid
    print("Passed")
    return True
