"""
This file will act as the centralization necessary to implement the Proof of Stake Algorithm
It will perform the selection of validators and consensus of blocks
"""


# imports
from all_imports import *

class Validator:
    def __init__(self, hash):
        self.id = hash
        self.port = port
        self.chain = []
        self.lasthash = None

class Server(threading.Thread):
    """
    This class is responsible for receiving and reacting to messages from nodes
    """

    def __init__(self, my_host, my_port):
        threading.Thread.__init__(self, name="consensus_server")
        logging.debug(f"Consensus server started at port {my_port}")
        self.host = my_host
        self.port = my_port
        self.hash = ne.new_node(my_port)

        # create encryption keys for this node (if needed)
        self.my_pr_key = ke.create_key(self.port)

        # create list to hold UtilityToken balances of each node
        self.walletList = {}

        # list of validators for the next block
        self.validator_list = []

        # create blockchain copy for the consensus server
        self.blockchain = []

        # create transaction list to indicate when
        self.transactions = ne.get_transactions(self.port)

        # Read in the blockchain of the smartcontract
        self.blockchain = bf.restore_chain(port=self.port)
        self.write_chain()

        self.lastIndex = len(self.blockchain)

        # update balances from stored chain
        self.update_wallets()

        # mimic global variables privately
        self.port_to_hash = {}
        self.hash_to_port = {}

    def listen(self):
        """
        This function is the listener for incoming messages
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
            # print(connection)

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

                        # print("\nreceived encrypted message:",full_message)

                        # decrypt received message using known key:
                        full_message = crypt.decrypt(full_message, self.my_pr_key)

                        # print("\ndecrypted message:", full_message)

                        try:
                            # load the message structure
                            msgJson = json.loads(full_message)

                            # load the data structure that the message is carrying
                            msgData = json.loads(msgJson['data'])
                            # print("msgJson", msgJson)

                        # Exception catch from message conversion to json
                        except Exception as e:
                            print(f"Error decoding received message: {e}")
                            logging.error(f"Error decoding received message at port {self.port}: {e}")
                            break

                        # reaction to introduction
                        if msgJson['type'] == "intro" and msgJson['to'] == self.port:
                            # map sender's hash to its local port and give it a unique identifier
                            if msgData['fromport'] not in self.port_to_hash:
                                sha = hasher.sha256()
                                sha.update(str(time.time()).encode(g.ENCODING))
                                # map sender's hash to its local port
                                self.port_to_hash[msgData['fromport']] = msgJson['from']
                                self.hash_to_port[msgJson['from']] = msgData['fromport']
                        if msgJson['type'] == "consensus":

                            vIndex = self.is_validator(msgJson['from'])
                            if vIndex is None:
                                # case when sender is not a validator
                                logging.warning(f"Consensus attempted by non-validator: {msgJson['from']}")
                                break
                            if self.validator_list[vIndex].lasthash is not None:
                                # case when sender has already sent one chain
                                logging.warning(f"Consensus attempted multiple times from {msgJson['from']}")
                                break

                            try:
                                loaded_chain = json.loads(msgData['chain'])
                            except Exception as e:
                                logging.warning(
                                    f"Consensus response received from {msgJson['from']} was not formatted correctly")

                            # store the sent chain
                            chain = json.loads(msgData['chain'])
                            if bf.validate(chain, msgData['lasthash']):
                                self.validator_list[vIndex].chain = chain

                                # store the sent hash
                                self.validator_list[vIndex].lasthash = msgData['lasthash']

                                if self.consensus_collected():
                                    self.validator_consensus()
                            else:
                                # case when validation fails
                                logging.warning(f"Consensus chain from {msgJson['from']} was invalid")


            finally:
                #connection.shutdown(2)
                connection.close()

    def validator_consensus(self):
        """
        This function will perform consensus among the assigned validators and issue punishment
        :return: None
        """
        votes = {}
        chains = []

        # accumulate the votes
        for i in self.validator_list:
            if i.lasthash in votes:
                votes[i.lasthash].append(i.id)
            else:
                votes[i.lasthash] = [i.id]
                chains.append(i.chain)

        # sort vote dict by quantity of nodes agreeing on a hash
        sorted_consensus = sorted(votes, key=lambda k: len(votes[k]), reverse=True)

        # distribute payment/punishment
        for count,i in enumerate(sorted_consensus):
            for j in i:
                if count:
                    self.pay(j, g.PENALTY)
                else:
                    self.pay(j, g.INCENTIVE)



    def consensus_collected(self):
        """
        This function will tell when the list of validators has finished collecting chains
        :return: Boolean for above case
        """
        for i in self.validator_list:
            if i.lasthash is None:
                return False
        return True

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

        :param port: Destination port
        :param value: UtilityToken Value (negative for penalty)
        :return: None
        """
        if self.walletList[destHash]+value < 0:
            # minimum account value is 0 (this means they will have a 0% chance of being chosen as a validator)
            value = -self.walletList[destHash]

        # double check if node exists
        if destHash in self.hash_to_port:

            # broadcast payment to all nodes
            for i in self.hash_to_port:
                message = json.dumps({
                    "type": "payment",
                    "from": self.hash,
                    "to": destHash,
                    "data": json.dumps({"value": value}),
                    "time": time.time()
                })
                comm.sendMessage(message, self.hash_to_port[i], self.my_pr_key)

        # record payment in own transactions list
        self.transactions = bf.add_transaction(time.time(), "payment", self.hash, destHash,
                                               value, listOfTransactions=self.transactions)
        ne.update_transactions(port=self.port, transactions=self.transactions)

        # update affected wallet
        self.walletList[destHash] += value


    def validator_select(self):
        """
        This function will select random nodes weighted by their UtilityToken Balance to be validator nodes
        :return: None
        """

        # turn balances into weights
        weightList = list(self.walletList.values())

        # make list of the hash ids
        hashList = list(self.walletList.keys())

        # clear the current validators
        self.validator_list = []

        # Pick a random number of validators for the next block
        for i in range(random.randint(1,10)):
            if len(hashList):
                # make random weighted choice based on UtilityToken 'Balance'
                choice = random.choices(range(0,len(hashList)), weights=weightList, k=1)[0]

                # add selection to list
                self.validator_list.append(Validator(hashList[choice]))

                # pop for non-repeating
                hashList.pop(choice)
                weightList.pop(choice)
            else:
                break


    def is_validator(self, hash):
        """
        This function will return the index if the hash provided is in the validator list
        :param hash: the hash to check
        :return: index of hash in the validator list
        """

        for i in range(0, len(self.validator_list)):
            if self.validator_list[i].hash == hash:
                return i
        return None

    def run(self):
        """
        Run the thread
        :return: None
        """
        self.listen()


def main():
    # format the log
    logging.basicConfig(filename='Storage/blockchain.log', filemode='a',
                        format='%(asctime)s %(levelname)s: %(message)s',
                        level=logging.DEBUG)

    # run the consensus server
    Server(g.BASE_HOST, g.BASE_PORT)


if __name__ == '__main__':
    """
    This executes the main function only if the module is run directly
    """

    main()
