"""
This file contains functions and classes related to the blockchain and transactions
This includes the general structure, consensus, validation, manipulation, data types, etc.
"""

# imports
from all_imports import *

######### BLOCKCHAIN CODE ##################


class Block:
    """
    This class defines the structure of a block
    """
    def __init__(self, index, timestamp, data, previous_hash):
        """
        This function initializes a block
        :param index: index of this block
        :param timestamp: timestamp of this block
        :param data: data to be included in this block (transactions)
        :param previous_hash: hash of previous block in the chain
        """
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.hash_block()

    def hash_block(self):
        """
        This function returns the hash of this block, using the index, timestamp, data, and previous hash
        """
        sha = hasher.sha256()
        sha.update((str(self.index) + str(self.timestamp) + str(self.data) + str(self.previous_hash)).encode())
        return sha.hexdigest()

    def to_dict(self):
        """
        This function returns a dict of this block's fields
        :returns:
        """
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
        :param trans_type: Transaction type
        :param sender: hash of node sending power reference
        :param recipient: hash of node sending sensitivity
        :param value: value associated with the transaction (power reference, sensitivity, or UtitlityToken)
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
        :param other: other transaction to compare with
        :returns: boolean of timestamp ordering (least to greatest time)
        """
        return self.timestamp < other.timestamp

    def hash_transaction(self):
        """
        This function returns the hash of this transaction
        """
        return get_hash(self.timestamp, self.type, self.sender, self.recipient, self.value)

    def to_dict(self):
        """
        This function returns a dictionary of this transactions fields
        :returns: dictionary of fields
        """
        return {
            "timestamp": self.timestamp,
            "type": self.type,
            "sender": self.sender,
            "recipient": self.recipient,
            "value": self.value,
            "hash": self.hash
        }

    def to_string(self):
        """
        This function string-ifies the transaction (was used for debugging purposes)
        :returns: string of fields
        """
        return f"Time:{self.timestamp}\n" \
               f"Type:{self.type}\n" \
               f"Sender:{self.sender}\n" \
               f"Recipient:{self.recipient}\n" \
               f"Value:{self.value}\n" \
               f"Hash:{self.hash}\n"


def get_hash(*s):
    """
    This function will return a SHA256 hash of the variables(s) provided

    :param s: arbitrary number of arguments to be combined into a string then converted to a hash
    :returns: hash of arguments provided
    """

    # combines arguments into a string
    hashString = ""
    for i in s:
        hashString += str(i)

    # convert string into SHA256 hash
    sha = hasher.sha256()
    sha.update(hashString.encode(g.ENCODING))

    return sha.hexdigest()


def get_dict_list(chainList=None):
    """
    This function returns a dictionary list of a given list of objects (Blocks or Transactions)
    :param chainList: list to get objects from, default None results in global blockchain used
    :returns: returns local blockchain in dictionary form
    """

    # update default parameter
    if chainList is None:
        chainList = g.blockchain

    # create a list to return
    chain_to_send = []

    # add dictionaries to list
    for i in chainList:
        chain_to_send.append(i.to_dict())

    return chain_to_send


def get_block_objs(chainDict):
    """
    This function will do the opposite of :meth:`blockchain_funcs.get_dict_list`, it will take a dictionary list and turn it
    into a list of :class:`blockchain_funcs.Block` objects, used to copy chains from messages

    :param chainDict: the dict list to copy
    :returns: list of block objects
    """
    # create a list to return
    listToReturn = []
    # create and append block objects from the dictionaries
    for i in chainDict:
        listToReturn.append(Block(i["index"], i["timestamp"], i["data"], i["previous_hash"]))

    return listToReturn


def get_trans_objs(chainDict):
    """
    This function will take a dictionary list and turn it into a list of :class:`blockchain_funcs.Transaction` objects

    :param chainDict: the dict list to convert to blocks
    :returns: list of block objects
    """
    # create list to return
    listToReturn = []
    # create and append Transaction objects from the dictionaries
    for i in chainDict:
        listToReturn.append(Transaction(i["timestamp"], i["type"], i["sender"], i["recipient"], i["value"]))

    return listToReturn


def restore_chain(port=g.my_port):
    """
    This function will restore a blockchain from local storage or generate a genesis block
    if there is no chain stored

    :param port: port of the node restoring its blockchain
    :returns: the restored blockchain
    """
    import node_editor as ne

    # Read json from storage
    with open(f"Storage/NodeData/node{port}.json", "r") as f:
        node_file, successful = ne.tryLoad(f, port)

    if not successful:
        logging.warning(f"unable to read chain for port: {port} FINAL")
        return

    # create
    chainToReturn = []

    # if there is a chain, retrieve what is stored there
    if len(node_file["chain"]):
        chainToReturn = get_block_objs(node_file["chain"])

    # if nothing was retrieved from storage, create a genesis block
    if not len(chainToReturn):
        chainToReturn.append(create_genesis_block())

    return chainToReturn


def add_transaction(timestamp, type, sender, recip, value, listOfTransactions=None, port=g.my_port, my_chain=None):
    """
    This function will 'insort' a transaction into this nodes transaction list based on the confirmation timestamp

    :param timestamp: Timestamp of transaction confirmation
    :param type: type of transaction being added
    :param sender: sender of the transaction
    :param recip: recipient of the transaction
    :param value: value associated with the transaction
    :param listOfTransactions: provided list of transactions to add this transaction to
    :param port: port of the node adding the transaction for debugging
    :param my_chain: blockchain of the node adding the transaction
    :returns: updated list of transactions
    """
    # update default parameters
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

        # debugging
        print(f"adding transaction at port {port}, new size: {len(listOfTransactions)}")
        logging.debug(f"adding transaction at port {port}, new size: {len(listOfTransactions)} "
                      f"(hash: {transaction_to_add.hash}, T_time:{timestamp} > B_time(i:{my_chain[-1].index}):{my_chain[-1].timestamp})")

    return listOfTransactions


def get_transaction_list_hash(this_list=None):
    """
    This function will hash together the list of transactions

    :param this_list: can specify a different list to hash
    :returns: the resulting hash
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


def create_genesis_block(prev=None):
    """
    This function creates the genesis block upon this node's instantiation.
    This is only relevant if it is the first node in the system, as all other nodes will
    seek consensus and throw away their genesis block

    :returns: returns the object of a genesis block
    """

    if prev is None:
        prev = "0"

    # Manually construct a block with
    # index zero and arbitrary previous hash
    return Block(0, time.time(), {
        "transactions": []
    }, prev)


def consensus_and_reset(threadNum=None):
    """
    This function will call consensus and reset its variables
    (used as the timeout callback)
    """
    g.blockchain = consensus()
    reset_consensus(g.blockchain[-1].index)


def consensus_reset_and_send(threadNum=None):

    import communication as comm

    g.blockchain = consensus()

    # record completion of this node's consensus
    dr.write_msg_time(get_hash(g.blockchain[-1].index, g.my_port), "consensus_process", g.consensus_index, g.my_port)

    logging.debug(
        f"Node {g.my_port} is sending consensus to the smartcontract for index {g.blockchain[-1].index} with {len(g.consensus_id_list)} votes out of {len(g.node_list) + 1}")

    reset_consensus(g.blockchain[-1].index)

    # double check that we're a validator
    if g.my_hash in g.validator_list:
        # send consensus result to the smart contract
        try:
            # set traitor
            if g.my_port in g.TRAITOR_PORTS:
                # idx = -1
                idx = random.choices([-1, 0], weights=[80, 20], k=1)[0]
                if not idx:
                    logging.warning(f"Traitor {g.my_port} is doing its interfering (contract)")
                    # send a different block
                    # g.blockchain[-1] = create_genesis_block(g.blockchain[-1].previous_hash)
                    # idx = -1
                    return    # cause timeout error
            else:
                idx = -1
            message = {
                "type": "consensus",
                "from": g.my_hash,
                "to": g.port_to_hash[g.BASE_PORT],
                "data": {
                    "lasthash": g.blockchain[idx].hash,
                    "newblock": g.blockchain[idx].to_dict(),
                    "transactions": get_dict_list(chainList=g.this_nodes_transactions)
                },
                "time": time.time()
            }
            comm.sendMessage(message, g.BASE_PORT)
        except Exception as e:
            logging.warning(f"Couldn't send chain from {g.my_port} to smart contract because {e}")


def consensus(chainList=None, port=g.my_port, cons_array=None, cindex=None,
              chain_dict=None, trans_dict=None, id_list=None,
              trans_vote_dict=None):
    """
    This function is responsible for enacting consensus on this node's blockchain.
    Once all "votes" have been received or the time window has expired, the most popular
    "vote" is copied to our blockchain if it is agreed upon by >50% of the nodes

    :param chainList: current or specified blockchain
    :param port: port of enacting node
    :param cons_array: dictionary/ of votes for consensus
    :param cindex: index of last agreed block
    :param chain_dict: dictionary of blockchains being voted on
    :param trans_dict: dictionary of transactions being voted on
    :param id_list: list of nodes that voted
    :param trans_vote_dict: dictionary of votes for the transactions
    :returns: consensus-agreed chain
    """

    # local import because of cyclical nature
    import node_editor as ne

    # make sure global variable references are updated (default parameters aren't dynamic)
    if chainList is None:
        chainList = g.blockchain
    if trans_dict is None:
        trans_dict = g.trans_dict
    if trans_vote_dict is None:
        trans_vote_dict = g.trans_vote_dict
    if cons_array is None:
        cons_array = g.consensus_array
    if cindex is None:
        cindex = g.consensus_index
    if chain_dict is None:
        chain_dict = g.chain_dict
    if id_list is None:
        id_list = g.consensus_id_list

    if g.addblock_timer_thread:
        logging.debug(f"Addblock timer STOPPED at node {port}")
        g.addblock_timer_thread.stop()
        g.addblock_timer_thread = None
    if g.response_timer_thread:
        logging.debug(f"Response timer STOPPED at node {port}")
        g.response_timer_thread.stop()
        g.response_timer_thread = None

    if not len(cons_array):
        return chainList

    # sort consensus dict by quantity of nodes agreeing on a hash
    popular_choice = max(set(cons_array), key=cons_array.count)

    # debugging
    # print(f"before consensus performed, chain: {blockchain[-1].hash}")
    # print(f"g.consensus_time: {g.consensus_time}")
    # print(f"g.consensus_dict: {g.consensus_dict}")
    # print(f"sorted_consensus: {sorted_consensus}")

    # If most popular choice has > than half of all voting nodes agreeing
    # (excluding consensus server), go with that choice
    if popular_choice and cons_array.count(popular_choice) > (len(cons_array))/2:

        # erase any blocks in our chain that have not been agreed on
        while len(chainList) and chainList[-1].index > cindex:
            logging.debug(f"node: {port} bf_consensus (idx:{cindex}) popping {chainList[-1].hash}")
            chainList.pop(len(chainList)-1)

        # logging.debug(f"node: {port} about to push chain: {popular_choice} from:\n{chain_dict}")

        # add each block to our blockchain that is older than we've already agreed on
        for i in chain_dict[popular_choice]:
            if i['index'] > cindex:
                chainList.append(Block(i['index'], i['timestamp'], i['data'], i['previous_hash']))
                logging.debug(f"node: {port} bf_consensus adding {chainList[-1].hash}")
                cindex = i['index']

        print(f"Consensus performed, resulting chain: {chainList[-1].hash}")
        logging.debug(f"Consensus performed, resulting chain: {chainList[-1].hash}")

    else:
        # case when popular choice is not agreed on by more than half of the voting nodes
        logging.warning(f"consensus failed: popular choice <= half of all nodes, at port {port}: votes:{cons_array}")
        print(f"Consensus failed: popular choice <= half of all nodes, at port {port}")
        return chainList

    # insort popular transactions that are not in our transactions already
    for i in trans_vote_dict.keys():
        if len(trans_vote_dict[i]) > (len(id_list))/2:
            g.this_nodes_transactions = add_transaction(trans_dict[i].timestamp, trans_dict[i].type,
                                                           trans_dict[i].sender, trans_dict[i].recipient,
                                                           trans_dict[i].value, listOfTransactions=None,
                                                           port=port, my_chain=chainList)

    logging.debug(f"Transaction Consensus completed at node {port}, resulting size:{len(g.this_nodes_transactions)}")

    # update local storage with the chain and transactions
    ne.update_chain(chainList=chainList, port=port)
    ne.update_transactions(port=port, transactions=g.this_nodes_transactions)

    return chainList


def in_transactions(t_hash, t_list=None):
    """
    This function will tell if a transaction has already been recorded
    :param t_hash: hash of transaction to search for
    :param t_list: list of transactions
    :returns: Boolean representing whether the transaction was found
    """
    # update default parameters
    if t_list is None:
        t_list = g.this_nodes_transactions

    # check for a transaction with the same hash
    for i in t_list:
        if i.hash == t_hash:
            return True

    return False


def reset_consensus(newIndex):
    """
    This function resets global variables used for consensus
    :param newIndex: new index of consensus_index used to keep track of the last agreed block
    """

    logging.debug(f"node {g.my_port} consensus reset")
    # Reset consensus variables
    g.consensus_id_list = []
    g.consensus_array = []
    g.trans_dict = {}
    g.trans_vote_dict = {}
    g.chain_dict = {}
    g.consensus_index = newIndex


def add_trans_to_block():
    """
    This function will add a block's transactions to their blockchain according to the BLOCK_SIZE
    """
    # local import because bf is imported after node editor
    import node_editor as ne

    # index of current last block
    prevIndex = g.blockchain[-1].index

    # hash of current last block
    prevHash = g.blockchain[-1].hash

    # get dictionary list of transactions to add to a block
    transactions_to_add = get_dict_list(g.this_nodes_transactions[:g.BLOCK_SIZE])

    # just re-use the timestamp of the last transaction received for consistency across nodes
    blocktime = transactions_to_add[-1]['timestamp']

    # create and append a new block using the above variables
    g.blockchain.append(Block(prevIndex + 1, blocktime, {
        "transactions": transactions_to_add
    }, prevHash))


    logging.debug(f"Node at port {g.my_port} is adding index {g.blockchain[-1].index} to its blockchain with hash: {g.blockchain[-1].hash}")

    # slice off the transactions added to the blockchain
    g.this_nodes_transactions = g.this_nodes_transactions[g.BLOCK_SIZE:]

    print(f"adding to my blockchain, new lasthash: {g.blockchain[-1].hash}")

    # save changes to local memory
    ne.update_transactions()
    ne.update_chain()


def validate(chain, lasthash, index=None,fromport=None):
    """
    This function validates a chain against itself and its proposed hash

    :returns: boolean value representing validity of the provided chain and hash
    """

    # update the default variable
    if index is None:
        index = g.consensus_index

    print(f"Validating hash: {lasthash}")

    calculated_hash = get_hash(chain[0]['index'], chain[0]['timestamp'], chain[0]['data'], chain[0]['previous_hash'])

    # initialize the hash
    if len(chain) > 1:
        # check validity of provided g.blockchain (for every block after the first)
        for i in range(1, len(chain)):
            # if fail to reproduce the same hash as what's stored in the current block,
            # or fail to reproduce 'previous hash' of the next block, then blockchain is invalid
            if (calculated_hash != chain[i]['previous_hash'])\
                    or calculated_hash != chain[i-1]['hash']:
                print("Failed: bad chain")
                logging.warning(f"Validation failed at port {g.my_port} from port {fromport}: chain of {lasthash} was invalid, calculated hash: {calculated_hash}")
                return False

            # reproduce the hash from the data in each block
            calculated_hash = get_hash(chain[i]['index'], chain[i]['timestamp'], chain[i]['data'],
                                       chain[i]['previous_hash'])


    # check final hash against provided hash
    # also check that the provided blockchain is longer than what we've agreed on already
    if lasthash != calculated_hash or lasthash != chain[-1]['hash']:
        print("Failed: bad hash/index")
        logging.warning(f"Validation failed: hash did not match it's chain: {lasthash}!={calculated_hash}")
        return False
    if index >= chain[-1]['index']:
        logging.warning(f"Validation failed: chain did not exceed consensus index: {g.consensus_index} >= {chain[-1]['index']}")
        return False

    # If nothing failed, then the chain is valid
    print("Passed")
    return True
