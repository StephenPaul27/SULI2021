"""
This file will act as the centralization necessary to implement the Proof of Stake Algorithm
It will perform the selection of validators and consensus of blocks
"""


# imports
from all_imports import *


class Server(threading.Thread):
    """
    This class is responsible for receiving and reacting to messages for the "smart contract" server
    """

    def __init__(self, my_host=g.BASE_HOST, my_port=g.BASE_PORT):
        """
        This function initializes the server and its variables
        :param my_host: host of the server (defaults to BASE)
        :param my_port: port of the server (defaults to BASE)
        """

        # Start the thread for the server
        threading.Thread.__init__(self, name="consensus_server")
        logging.debug(f"Consensus server started at port {my_port}")

        # set host and port of server
        self.host = my_host
        self.port = my_port

        # open new file if needed for the node data
        with open(f"Storage/NodeData/node{self.port}.json", "w+") as f:
            # if file is not formatted as json, format it as an empty json
            try:
                json.load(f)
            except json.JSONDecodeError:
                json.dump({}, f, ensure_ascii=False, indent=4, sort_keys=True)
            else:
                # if rewriting files, erase the written file
                if g.REWRITE_FILES:
                    json.dump({}, f, ensure_ascii=False, indent=4)

        # erase validators if rewriting files
        if g.REWRITE_FILES:
            with open("Storage/balances.csv", 'r+') as f:
                f.truncate(0)

            with open("SmartContracts/contractStorage.json", "w") as f:
                json.dump({
                    "index": -1,
                    "validators": []
                }, f, ensure_ascii=False, indent=4)

        self.max_validators = 10

        # create the hash for this node (if needed)
        self.hash = ne.new_node(my_port)

        # create encryption keys for this node (if needed)
        self.my_pr_key = ke.create_key(self.port)

        # create list to hold UtilityToken balances of each node
        self.walletList = {}

        # list of validators for the next block
        self.validator_list = []

        # consensus dictionary
        self.votes = {}

        # list of validators who have voted
        self.voted_validators = []

        # dicts for storing chains and transactions for consensus
        self.chains_dict = {}
        self.trans_dict = {}

        # create transaction list
        self.transactions = ne.get_transactions(self.port)

        # Read in the blockchain of the smartcontract
        self.blockchain = bf.restore_chain(port=self.port)
        ne.update_chain(port=self.port, chainList=self.blockchain)

        # store the last agreed index
        self.lastIndex = self.blockchain[-1].index

        # update wallet balances from stored chain
        self.update_wallets()

        # dictionaries to track other nodes online
        self.port_to_hash = {}
        self.hash_to_port = {}

        # restore validators and index from memory if they're up to date
        self.read_validators()

    def listen(self):
        """
        This function is the listener for the server, it accepts connections and messages
        :return: None
        """

        # create server socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(g.NUM_NODES)
        # print("server started")

        # while loop to accept incoming connections/messages
        while True:

            # accept client connection
            connection, client_address = sock.accept()
            # logging.debug("\nconnection started at consensus server\n")

            try:
                full_message = b''

                # while loop to read in data from incoming message
                while True:

                    # Receive 2048 bytes at a time
                    data = connection.recv(2048)

                    # accumulate the bytes into the message
                    full_message = full_message + data
                    # print("data:"+str(data))

                    # once data has stopped coming in, decode the message
                    if not data:
                        # break immediately if empty message
                        if full_message is None or full_message == b'':
                            logging.debug(f"Received blank message at port {self.port}")
                            break

                        # print("\nreceived encrypted message:",full_message)

                        # decrypt received message using known key:
                        full_message = crypt.decrypt(full_message, port=self.port, pr_key=self.my_pr_key)

                        # print("\ndecrypted message:", full_message)

                        try:
                            # load the message structure
                            msgJson = json.loads(full_message)

                            # Extract the data structure that the message is carrying
                            msgData = msgJson['data']

                        # Exception catch from message conversion to json
                        except json.JSONDecodeError as e:
                            print(f"Error loading json message: {e}")
                            logging.error(f"Error loading json from message at port {self.port}: {e}")
                            break

                        # in the initial handshake process, store ports and hashes
                        if msgJson['type'] == "intro" or msgJson['type'] == 'response':
                            # if this port has not already been assigned
                            if msgData['fromport'] not in self.port_to_hash:
                                # map sender's hash to its local port and vice versa
                                self.port_to_hash[msgData['fromport']] = msgJson['from']
                                self.hash_to_port[msgJson['from']] = msgData['fromport']

                        # reaction to introduction
                        if msgJson['type'] == "intro" and msgJson['to'] == self.port:
                            self.introduction_response(msgJson, msgData)
                        # reaction to consensus initiation
                        elif msgJson['type'] == "consensus":
                            self.consensus_response(msgJson, msgData)

                        # break out of message data action
                        break

            finally:
                # logging.debug("\nconnection closed at consensus server\n")
                # connection.shutdown(2)
                connection.close()

    def consensus_response(self, msgJson, msgData):
        """
        This function reacts to consensus messages, collecting consensus results from the validators then
        performing its own consensus using those blockchains

        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
        :return: None
        """

        # obtain the index of the message sender hash in the validator list
        # if it does not exist (i.e. the sender is not a validator) it will return None
        vIndex = self.is_validator(msgJson['from'])

        if vIndex is None:
            # case when sender is not a validator
            logging.warning(f"Consensus attempted by non-validator: {msgJson['from']}")
            return
        if self.validator_list[vIndex] in self.voted_validators:
            # case when sender has already sent one chain
            logging.warning(f"Consensus attempted multiple times from {msgJson['from']}")
            return

        # mark the validator as already having voted once in this cycle
        self.voted_validators.append(self.validator_list[vIndex])

        # load the transactions from the message
        loaded_transactions = bf.get_trans_objs(msgData['transactions'])

        # get the hash of those transactions
        T_hash = bf.get_transaction_list_hash(loaded_transactions)

        # create combination hash of transactions and blockchain
        comboHash = bf.get_hash(str(msgData['lasthash']) + str(T_hash))

        # if the hash is already in the votes
        if comboHash in self.votes:
            # append this validator's vote to it
            self.votes[comboHash].append(self.validator_list[vIndex])
        # else, validate the chain and hash
        elif bf.validate(msgData['chain'], msgData['lasthash'], index=self.lastIndex):
            # then create the first vote for this comboHash
            self.votes[comboHash] = [self.validator_list[vIndex]]
            # store the chain being voted on
            self.chains_dict[comboHash] = msgData['chain']
            # store the transactions being voted on
            self.trans_dict[comboHash] = loaded_transactions

        # if all validators have voted
        if len(self.voted_validators) == len(self.validator_list):
            # perform consensus
            self.validator_consensus()
            # reset the consensus variables
            self.reset_consensus()

        else:
            # case when validation fails
            logging.warning(f"Consensus chain from {msgJson['from']} was invalid")

    def introduction_response(self, msgJson, msgData):
        """
        This function is responsible for responding to the introduction message of a new node

        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
        :return: None
        """

        # respond with port in the data
        # include list of validators as well so the new node knows whether to do consensus

        message = {
            "type": "response",
            "from": self.hash,
            "to": msgJson['from'],
            "data": {
                        "fromport": self.port,
                        "validators": self.validator_list
                    },
            "time": time.time()
        }
        try:
            # send the message
            comm.sendMessage(message, int(msgData['fromport']), self.my_pr_key)
        except Exception as e:
            print("could not respond to introduction because", e)
            logging.error(f"port {self.port} could not respond to introduction because {e}")
            # breakpoint()

        # set up balance for completely new nodes not yet present in the blockchain
        if msgJson['from'] not in self.walletList:
            # start nodes with 20 utility tokens or the median value of current wallets, whichever is higher
            amount = 20
            if len(self.walletList):
                med = statistics.median(list(self.walletList.values()))
                if med > amount:
                    amount = med
            # pay automatically updates or creates the local wallet
            self.pay(destHash=msgJson['from'], value=amount)

            # save wallet values to csv
            dr.write_balances(self.walletList, self.lastIndex)

        # if no validators were selected before this node, select this node
        if not len(self.validator_list):
            self.validator_select()

    def validator_consensus(self):
        """
        This function will perform consensus among the assigned validators and issue punishment
        :return: None
        """

        # sort vote dict by quantity of nodes agreeing on a hash
        sorted_consensus = sorted(self.votes, key=lambda k: len(self.votes[k]), reverse=True)
        print("performing consensus at the smart contract")
        if len(sorted_consensus):
            self.blockchain = bf.get_block_objs(self.chains_dict[sorted_consensus[0]])
            self.transactions = self.trans_dict[sorted_consensus[0]]
            ne.update_chain(self.port, self.blockchain)
            ne.update_transactions(self.port, self.transactions)

            # distribute payment/punishment
            for count, i in enumerate(sorted_consensus):
                for j in self.votes[i]:
                    print(f"paying {j}")
                    logging.debug(f"Smart-Contract Paying {j}")
                    # penalize everyone past index 0
                    if count:
                        self.pay(j, g.PENALTY)
                    # pay the hashes in index 0 because its sorted by majority
                    else:
                        self.pay(j, g.INCENTIVE)

            print(f"Updated Wallet values: {list(self.walletList.values())}")

            # update validators
            self.check_validators()

            # save wallet values to csv
            dr.write_balances(self.walletList, self.lastIndex)

    def reset_consensus(self):
        """
        This function will clear consensus server variables
        :return: None
        """
        self.chains_dict = {}
        self.trans_dict = {}
        self.votes = {}
        self.voted_validators = []

    def update_wallets(self):
        """
        This function will scan the blockchain to assign current balances for the nodes
        :return: None
        """

        # reinitialize walletList before adding to it
        self.walletList = {}

        # accumulate balances
        for i in self.blockchain:
            for j in i.data['transactions']:
                if j['from'] == self.hash:
                    # if balance exists, already, add to it, else set it
                    try:
                        self.walletList[j['to']] += j['value']
                    except KeyError:
                        self.walletList[j['to']] = j['value']

        # go through current transactions
        for i in self.transactions:
            # if balance exists, already, add to it, else set it
            try:
                self.walletList[i.recipient] += i.value
            except KeyError:
                self.walletList[i.recipient] = i.value

    def pay(self, destHash, value):
        """
        This function will send an official message of transfer of UtilityTokens

        :param destHash: Destination port
        :param value: UtilityToken Value (negative for penalty)
        :return: None
        """

        # create wallet if not available already
        try:
            self.walletList[destHash] += 0
        except KeyError:
            self.walletList[destHash] = 0

        if self.walletList[destHash]+value < 0:
            # minimum account value is 0 (this means they will have a 0% chance of being chosen as a validator)
            value = -self.walletList[destHash]

        # double check if node exists
        if destHash in self.hash_to_port:

            timeToSend = time.time()

            # broadcast payment to all nodes, including the correct chain for faulty
            # nodes to correct themselves with
            for i in self.port_to_hash:
                message = {
                    "type": "payment",
                    "from": self.hash,
                    "to": destHash,
                    "data": {
                                "value": value,
                                "lasthash": self.blockchain[-1].hash,
                                "chain": bf.get_dict_list(self.blockchain)
                            },
                    "time": timeToSend
                }
                try:
                    comm.sendMessage(message, i, self.my_pr_key)
                except Exception as e:
                    logging.error(f"port {self.port} could not send payment receipt to port {i} because: {e}")

            # record payment in own transactions list
            self.transactions = bf.add_transaction(timeToSend, "payment", self.hash, destHash,
                                                   value, listOfTransactions=self.transactions, port=self.port)
            ne.update_transactions(port=self.port, transactions=self.transactions)

            # update/create affected wallet
            self.walletList[destHash] += value


    def validator_select(self):
        """
        This function will select random nodes weighted by their UtilityToken Balance to be validator nodes
        :return: None
        """

        # make sure there are participants visible to the server
        if len(self.walletList):

            # turn balances into weights
            weightList = list(self.walletList.values())

            # make list of the hash ids
            hashList = list(self.walletList.keys())

            # clear the current validators
            self.validator_list = []
            self.lastIndex = self.blockchain[-1].index

            # pick random number of validators up to the max set value
            if len(hashList) > self.max_validators:
                numValidators = random.randint(1, len(self.max_validators))
            else:
                numValidators = random.randint(1, len(hashList))

            # pick out the validators
            for i in range(numValidators):
                if len(hashList):
                    # make random weighted choice based on UtilityToken 'Balance'
                    choice = random.choices(range(0, len(hashList)), weights=weightList, k=1)[0]

                    # add selection to list
                    self.validator_list.append(hashList[choice])

                    # pop for non-repeating
                    hashList.pop(choice)
                    weightList.pop(choice)
                else:
                    break

            print(f"selected new validators:{self.validator_list}")

            # broadcast newly selected validators to all of the nodes
            self.broadcast_validators()

            # update validators in memory
            self.write_validators()

    def is_validator(self, hash):
        """
        This function will return the index if the hash provided is in the validator list
        :param hash: the hash to check
        :return: index of hash in the validator list
        """

        for i in range(len(self.validator_list)):
            if hash == self.validator_list[i]:
                return i

        return None

    def check_validators(self):
        """
        This function will check if the validators need to be updated
        :return:
        """
        # checks if blockchain index is greater than current validator index
        if self.lastIndex < self.blockchain[-1].index:
            self.validator_select()

    def broadcast_validators(self):
        # broadcast current validators anyway
        for i in self.port_to_hash:
            message = {
                "type": "validators",
                "from": self.hash,
                "to": self.port_to_hash[i],
                "data": {
                            "validators": self.validator_list
                        },
                "time": time.time()
            }
            try:
                comm.sendMessage(message, i, self.my_pr_key)
            except Exception as e:
                logging.error(f"Couldn't broadcast validators to port {i} because: {e}")

    def read_validators(self):
        """
        This function will read the validators stored in memory
        :return:
        """
        # Read json from storage
        with open("SmartContracts/contractStorage.json", "r") as f:
            node_file = json.load(f)

        # if index in memory is somehow outdated, choose new validators
        if node_file["index"] < self.lastIndex:
            self.validator_select()
        else:
            self.validator_list = node_file["validators"]
            self.lastIndex = node_file["index"]
            self.broadcast_validators()


    def write_validators(self):
        """
        This function will write the validators to memory
        :return:
        """
        # Read json from storage
        with open("SmartContracts/contractStorage.json", "r") as f:
            node_file = json.load(f)

        node_file["validators"] = self.validator_list
        node_file["index"] = self.lastIndex

        # Write the updated json back to the file
        with open("SmartContracts/contractStorage.json", "w") as f:
            json.dump(node_file, f, ensure_ascii=False, indent=4, sort_keys=True)


    def run(self):
        """
        Run the thread
        :return: None
        """
        self.listen()


def main():
    # format the log

    if g.REWRITE_FILES:
        logMode = 'w'
    else:
        logMode = 'a'
    logging.basicConfig(filename='Storage/blockchain.log', filemode=logMode,
                        format='%(asctime)s %(levelname)s: %(message)s',
                        level=logging.DEBUG)

    # run the consensus server
    Server(g.BASE_HOST, g.BASE_PORT)


if __name__ == '__main__':
    """
    This executes the main function only if the module is run directly
    """

    main()
