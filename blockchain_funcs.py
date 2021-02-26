"""
This file contains functions and classes related to the blockchain
This includes the general structure, consensus, validation

"""

# imports
from all_imports import *

######### BLOCKCHAIN CODE ##################


class Block:
    """
    This class defines the structure of a block
    """
    # block structure
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.hash_block()

    def hash_block(self):
        """
        This function returns the hash of the local block, using the index, timestamp, data, and previous hash
        """
        sha = hasher.sha256()
        sha.update((str(self.index) + str(self.timestamp) + str(self.data) + str(self.previous_hash)).encode())
        return sha.hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": str(self.timestamp),
            "data": str(self.data),
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }

class Transaction:
    def __init__(self, timestamp, type, sender, recipient, value,):
        """
        This class is used to organize the transactions

        :param timestamp: Timestamp of transaction confirmation
        :param Pnode: hash of node sending power reference
        :param Snode: hash of node sending sensitivity
        :param power: power reference
        :param sense: sensitivity
        """

        self.timestamp = timestamp
        self.type = type
        self.sender = sender
        self.recipient = recipient
        self.value = value
        self.hash = self.hash_transaction()

    def __lt__(self, other):
        """
        This function defines the ordering of transactions based on timestamp

        :return: boolean of timestamp ordering (least to greatest time)
        """
        return self.timestamp < other.timestamp

    def hash_transaction(self):
        """
        This function returns the hash of the transaction
        """
        sha = hasher.sha256()
        sha.update((str(self.timestamp) + str(self.type) + str(self.sender) + str(self.recipient) + str(self.value)).encode())
        return sha.hexdigest()

    def to_string(self):
        return f"Time:{self.timestamp}\n" \
               f"Type:{self.type}\n" \
               f"Sender:{self.sender}\n" \
               f"Recipient:{self.recipient}\n" \
               f"Value:{self.value}\n" \
               f"Hash:{self.hash}\n"



def get_blocks():
    """
    This function returns a json-string of blocks in this node's blockchain

    :returns: returns local blockchain in dictionary form
    """
    # chain_to_send = blockchain
    chain_to_send = []

    # create list of block dicts to convert to json
    for i in range(len(g.blockchain)):
        chain_to_send.append(g.blockchain[i].to_dict())

    # convert to json
    chain_to_send = json.dumps(chain_to_send)

    return chain_to_send

def restore_chain():
    """
    This function will restore the blockchain from local storage

    :return: returns boolean, if false, generate genesis block
    """
    # Read json from storage
    with open("Storage/nodes.json", "r") as f:
        node_file = json.load(f)

    chain_file = None

    # return if node exists in file
    for i in list(node_file):
        if node_file[str(i)]["port"] == g.my_port:
            if node_file[str(i)]["chain"]:
                chain_file = json.loads(node_file[str(i)]["chain"])
            else:
                return False

    if chain_file:
        for i in list(chain_file):
            g.blockchain.append(Block(i["index"], i["timestamp"], i["data"], i["previous_hash"]))
        return True
    else:
        return False

def add_transaction(timestamp, type, sender, recip, value):
    """
    This function will 'insort' a transaction into this nodes transaction list based on the confirmation timestamp

    :param timestamp: Timestamp of transaction confirmation
    :param Pnode: hash of node sending power reference
    :param Snode: hash of node sending sensitivity
    :param power: power reference
    :param sense: sensitivity
    :return: None
    """

    # create the transaction object
    transaction_to_add = Transaction(timestamp, type, sender, recip, value)

    # insort the transaction based on its timestamp
    bisect.insort_left(g.this_nodes_transactions, transaction_to_add)

    # write to local storage
    ne.update_transactions()

    logging.debug(f"Recording complete transaction: {transaction_to_add.to_string()}")

def get_transaction_list_hash(this_list = g.this_nodes_transactions):
    """
    This function will hash together the list of transactions

    :param this_list: can specify a different list to hash
    :return: the resulting hash
    """

    # set arbitrary beginning hash
    sha = hasher.sha256()
    starting_hash = 100
    sha.update(str(starting_hash))

    for i in this_list:
        # hash one transaction with previous transaction
        starting_hash = sha.update(str(i.hash)+str(sha.hexdigest()))

    return starting_hash

def create_genesis_block():
    """
    This function creates the genesis block upon this node's instantiation.
    This is only relevant if it is the first node in the system, as all other nodes will
    seek consensus and throw away their genesis block

    :return: returns the object of a genesis block
    """

    # Manually construct a block with
    # index zero and arbitrary previous hash
    return Block(0, date.datetime.now(), {
        "transactions": None
    }, "0")


def consensus():
    """
    This function is responsible for enacting consensus on this node's blockchain.
    Once all "votes" have been received or the time window has expired, the most popular
    "vote" is copied to our blockchain if it is agreed upon by >50% of the nodes
    """

    # sort consensus dict by quantity of nodes agreeing on a hash
    sorted_consensus = sorted(g.consensus_dict, key=lambda k: len(g.consensus_dict[k]), reverse=True)

    # debugging
    # print(f"before consensus performed, chain: {blockchain[-1].hash}")
    # print(f"g.consensus_time: {g.consensus_time}")
    # print(f"g.consensus_dict: {g.consensus_dict}")
    # print(f"sorted_consensus: {sorted_consensus}")

    # If most popular choice has > than half of all nodes agreeing, go with that choice
    if len(g.consensus_dict[sorted_consensus[0]]) > (len(g.node_list))/2:

        # erase any blocks in our chain that have not been agreed on
        while len(g.blockchain) and g.blockchain[-1].index > g.consensus_index:
            g.blockchain.pop(len(g.blockchain)-1)

        # add each block to our blockchain that is past what we've already agreed on
        for i in g.chain_dict[sorted_consensus[0]]:
            if i['index'] > g.consensus_index:
                g.blockchain.append(Block(i['index'], i['timestamp'], i['data'], i['previous_hash']))
                g.consensus_index = i['index']
    else:
        logging.warning(f"consensus error: popular choice <= half of all nodes, at port {g.my_port}")

    # Reset consensus variables
    g.consensus_count = 0
    g.consensus_dict = {}
    g.consensus_time = 0
    g.chain_dict = {}

    print(f"Consensus performed, resulting chain: {g.blockchain[-1].hash}")
    ne.update_chain()


def validate(chain, lasthash):
    """
    This function validates a chain against itself and its claimed hash

    :returns: boolean value representing validity of the provided chain and hash
    """
    print("Validating:", lasthash)
    # initialize the hash
    sha = hasher.sha256()
    sha.update((str(chain[0]['index']) + str(chain[0]['timestamp']) + str(chain[0]['data']) + str(chain[0]['previous_hash'])).encode())

    # check validity of provided g.blockchain (for every block after the first)
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
    if lasthash != sha.hexdigest() or (g.consensus_index >= chain[-1]['index']):
        print("Failed: bad hash/index")
        logging.warning(f"{lasthash} did not match it chain or was not long enough")
        return False

    # If nothing failed, then the chain is valid
    print("Passed")
    return True
