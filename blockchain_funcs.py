"""This file contains functions and classes related to the blockchain
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
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }

class Transaction:
    def __init__(self, timestamp, trans_type, sender, recipient, value):
        """
        This class is used to organize the transactions

        :param timestamp: Timestamp of transaction confirmation
        :param ttype: Transaction type
        :param sender: hash of node sending power reference
        :param recipient: hash of node sending sensitivity
        :param value: value of the transaction (power reference, sensitivity, or UtitlityToken)
        """

        self.timestamp = timestamp
        self.type = trans_type
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

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "type": self.type,
            "sender": self.sender,
            "recipient": self.recipient,
            "value": self.value,
            "hash": self.hash
        }

    def to_string(self):
        return f"Time:{self.timestamp}\n" \
               f"Type:{self.type}\n" \
               f"Sender:{self.sender}\n" \
               f"Recipient:{self.recipient}\n" \
               f"Value:{self.value}\n" \
               f"Hash:{self.hash}\n"


def get_hash(hashString):
    """
    This function will return a SHA256 hash of the string provided

    :param hashString: string to hash
    :return: hash of string
    """
    sha = hasher.sha256()
    sha.update(hashString.encode(g.ENCODING))
    return sha.hexdigest()


def get_dict_list(chainList=None):
    """
    This function returns a dictionary list of a given list of objects
    :param chainList: list to get objects from, default None results in global blockchain used
    :returns: returns local blockchain in dictionary form
    """

    if chainList is None:
        chainList = g.blockchain

    # chain_to_send = blockchain
    chain_to_send = []

    # create list of block dicts to convert to json
    for i in chainList:
        chain_to_send.append(i.to_dict())

    return chain_to_send


def get_block_objs(chainDict):
    """
    This function will do the opposite of get_dict_list(), it will take a dictionary list and turn it
    into a list of Block objects, used to copy chains from messages

    :param chainDict: the dict list to copy
    :return: list of block objects
    """
    listToReturn = []
    for i in chainDict:
        listToReturn.append(Block(i["index"], i["timestamp"], i["data"], i["previous_hash"]))

    return listToReturn

def get_trans_objs(chainDict):
    """
    This function will take a dictionary list and turn it into a list of Transactions objects

    :param chainDict: the dict list to copy
    :return: list of block objects
    """
    listToReturn = []
    for i in chainDict:
        listToReturn.append(Transaction(i["timestamp"], i["type"], i["sender"], i["recipient"], i["value"]))

    return listToReturn


def restore_chain(port=g.my_port):
    """
    This function will restore the blockchain from local storage

    :return: returns boolean, if false, generate genesis block
    """
    # Read json from storage
    with open(f"Storage/NodeData/node{port}.json", "r") as f:
        node_file = json.load(f)

    chain_file = None
    chainToReturn = []

    # return if node exists in file
    if len(node_file["chain"]):
        chain_file = node_file["chain"]

    if chain_file:
        chainToReturn = get_block_objs(chain_file)

    if not len(chainToReturn):
        chainToReturn.append(create_genesis_block())

    return chainToReturn


def add_transaction(timestamp, type, sender, recip, value, listOfTransactions=None, port=g.my_port, my_chain=None):
    """
    This function will 'insort' a transaction into this nodes transaction list based on the confirmation timestamp

    :param timestamp: Timestamp of transaction confirmation
    :param Pnode: hash of node sending power reference
    :param Snode: hash of node sending sensitivity
    :param power: power reference
    :param sense: sensitivity
    :return: updated list of transactions
    """
    if listOfTransactions is None:
        listOfTransactions = g.this_nodes_transactions
    if my_chain is None:
        my_chain = g.blockchain
    # create the transaction object
    transaction_to_add = Transaction(timestamp, type, sender, recip, value)

    # check if transaction is new
    if not in_transactions(transaction_to_add.hash, listOfTransactions) \
            and timestamp > my_chain[-1].timestamp:

        # insort the transaction based on its timestamp
        bisect.insort_left(listOfTransactions, transaction_to_add)

        print(f"adding transaction at port {port}, new size: {len(listOfTransactions)}")
        logging.debug(f"adding transaction at port {g.my_port}, new size: {len(listOfTransactions)}")

    return listOfTransactions


def get_transaction_list_hash(this_list=None):
    """
    This function will hash together the list of transactions

    :param this_list: can specify a different list to hash
    :return: the resulting hash
    """

    # update optional parameter
    if this_list is None:
        this_list = g.this_nodes_transactions

    # set arbitrary beginning hash
    sha = hasher.sha256()
    starting_hash = 100
    sha.update(str(starting_hash).encode(g.ENCODING))

    for i in this_list:
        # hash one transaction with previous transaction
        sha.update((str(i.hash)+str(sha.hexdigest())).encode(g.ENCODING))

    return sha.hexdigest()


def create_genesis_block():
    """
    This function creates the genesis block upon this node's instantiation.
    This is only relevant if it is the first node in the system, as all other nodes will
    seek consensus and throw away their genesis block

    :return: returns the object of a genesis block
    """

    # Manually construct a block with
    # index zero and arbitrary previous hash
    return Block(0, time.time(), {
        "transactions": []
    }, "0")


def consensus(chainList=None, port=g.my_port, cons_dict=None, cindex=None, chain_dict=None, node_list=None, trans_dict=None):
    """
    This function is responsible for enacting consensus on this node's blockchain.
    Once all "votes" have been received or the time window has expired, the most popular
    "vote" is copied to our blockchain if it is agreed upon by >50% of the nodes

    :param chainList: current or specified blockchain
    :param port: port of enacting node
    :param cons_dict: dictionary/ of votes for consensus
    :param cindex: index of last agreed block
    :param chain_dict: dictionary of blockchains being voted on
    :param node_list: list of nodes connected
    :return: consensus-agreed chain
    """

    # local import because of cyclical nature
    import node_editor as ne

    # make sure global variable references are up to date (default parameters aren't dynamic)
    if chainList is None:
        chainList = g.blockchain
    if trans_dict is None:
        trans_dict = g.trans_dict
    if cons_dict is None:
        cons_dict = g.consensus_dict
    if cindex is None:
        cindex = g.consensus_index
    if chain_dict is None:
        chain_dict = g.chain_dict
    if node_list is None:
        node_list = g.node_list

    # sort consensus dict by quantity of nodes agreeing on a hash
    sorted_consensus = sorted(cons_dict, key=lambda k: len(cons_dict[k]), reverse=True)

    # debugging
    # print(f"before consensus performed, chain: {blockchain[-1].hash}")
    # print(f"g.consensus_time: {g.consensus_time}")
    # print(f"g.consensus_dict: {g.consensus_dict}")
    # print(f"sorted_consensus: {sorted_consensus}")

    # If most popular choice has > than half of all nodes agreeing (excluding consensus server), go with that choice
    if len(sorted_consensus) and len(cons_dict[sorted_consensus[0]]) > (len(node_list))/2:

        # erase any blocks in our chain that have not been agreed on
        while len(chainList) and chainList[-1].index > cindex:
            chainList.pop(len(chainList)-1)

        # add each block to our blockchain that is past what we've already agreed on
        for i in chain_dict[sorted_consensus[0]]:
            if i['index'] > cindex:
                chainList.append(Block(i['index'], i['timestamp'], i['data'], i['previous_hash']))
                cindex = i['index']

        print(f"Consensus performed, resulting chain: {chainList[-1].hash}")

        ne.update_chain(chainList=chainList, port=port)
        ne.update_transactions(port=port, transactions=trans_dict[sorted_consensus[0]])
    else:
        logging.warning(f"consensus failed: popular choice <= half of all nodes, at port {port}")
        print(f"Consensus failed: popular choice <= half of all nodes, at port {port}")
        return chainList, g.this_nodes_transactions



    return chainList, trans_dict[sorted_consensus[0]]


def in_transactions(t_hash,t_list=None):
    """
    This function will tell if a transaction has already been recorded
    :param t_hash: hash of transaction to search for
    :param t_list: list of transactions
    :return: Boolean representing whether the transaction was found
    """

    for i in t_list:
        if i.hash == t_hash:
            return True
    return False


def reset_consensus(newIndex):
    # Reset consensus variables
    g.consensus_dict = {}
    g.consensus_time = 0
    g.trans_dict = {}
    g.chain_dict = {}
    g.consensus_index = newIndex
    g.consensus_id_list = []


def add_trans_to_block():
    """
    This function will add a block's transactions to their blockchain according to the blocksize
    :return: None
    """
    # local import because bf is imported after node editor
    import node_editor as ne

    logging.debug(f"Node at port {g.my_port} is adding index {g.blockchain[-1].index+1} to its blockchain")
    prevIndex = g.blockchain[-1].index
    prevHash = g.blockchain[-1].hash
    transactions_to_add = get_dict_list(g.this_nodes_transactions[:g.BLOCK_SIZE])
    # just use the timestamp of the last transaction received for consistency
    blocktime = transactions_to_add[-1]['timestamp']
    g.blockchain.append(Block(prevIndex + 1, blocktime, {
        "transactions": transactions_to_add
    }, prevHash))
    # slice off the transactions added to the blockchain
    g.this_nodes_transactions = g.this_nodes_transactions[g.BLOCK_SIZE:]
    print(f"adding to my blockchain, new lasthash: {g.blockchain[-1].hash}")
    g.last_transactions_hash = get_transaction_list_hash(g.this_nodes_transactions)
    # save changes to local memory
    ne.update_transactions()
    ne.update_chain()


def validate(chain, lasthash, index=None,fromport=None):
    """
    This function validates a chain against itself and its claimed hash

    :returns: boolean value representing validity of the provided chain and hash
    """

    # update the default variable
    if index is None:
        index = g.consensus_index

    print(f"Validating hash: {lasthash}")
    # initialize the hash
    if len(chain) == 1:
        sha = hasher.sha256()
        sha.update((str(chain[0]['index']) + str(chain[0]['timestamp']) + str(chain[0]['data']) + str(chain[0]['previous_hash'])).encode())
        calculated_hash = sha.hexdigest()
    else:
        # check validity of provided g.blockchain (for every block after the first)
        for i in range(0, len(chain)):

            # reproduce the hash from the data in each block
            sha = hasher.sha256()
            sha.update((str(chain[i]['index']) + str(chain[i]['timestamp']) + str(chain[i]['data']) + str(chain[i]['previous_hash'])).encode())
            calculated_hash = sha.hexdigest()

            # if fail to reproduce the same hash as what's stored in the current block,
            # or fail to reproduce 'previous hash' of the next block, then blockchain is invalid
            if (i+1 < len(chain) and calculated_hash != chain[i + 1]['previous_hash'])\
                    or calculated_hash != chain[i]['hash']:
                print("Failed: bad chain")
                logging.warning(f"Validation failed at port {g.my_port} from port {fromport}: chain of {lasthash} was invalid, calculated hash: {calculated_hash}")
                return False

    # check final hash against provided hash
    # also check that the provided blockchain is longer than what we've agreed on already
    if lasthash != calculated_hash:
        print("Failed: bad hash/index")
        logging.warning(f"Validation failed: hash did not match it's chain: {lasthash}!={calculated_hash}")
        return False
    if index >= chain[-1]['index']:
        logging.warning(f"Validation failed: chain did not exceed consensus index: {g.consensus_index} >= {chain[-1]['index']}")
        return False

    # If nothing failed, then the chain is valid
    print("Passed")
    return True
