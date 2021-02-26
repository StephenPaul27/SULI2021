"""
This file will act as the centralization necessary to implement the Proof of Stake Algorithm
It will perform the selection of validators and consensus of blocks
"""


# imports
from all_imports import *

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

        # create list to hold UtilityToken balances of each node
        self.walletList = {}

        # create blockchain copy for the consensus server
        self.blockchain = []

        # mimic global variables privately
        self.port_to_hash = {}
        self.hash_to_port = {}
        self.identifier_dict = {}

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
                        full_message = crypt.decrypt(full_message)

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
                                # give it a unique identifier for securing later messages
                                self.identifier_dict[msgJson['from']] = sha.hexdigest()

            finally:
                #connection.shutdown(2)
                connection.close()

    def wallet_search(self):
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

    def pay(self, port, value):
        """
        This function will send an official message of transfer of UtilityTokens

        :param port: Destination port
        :param value: UtilityToken Value
        :return: None
        """
        # double check if node exists
        if port in self.port_to_hash:

            # broadcast payment to all nodes
            for i in self.hash_to_port:
                # send my hash to all existing nodes
                message = json.dumps({
                    "type": "payment",
                    "identifier": self.identifier_dict[i],
                    "from": self.hash,
                    "to": self.port_to_hash[port],
                    "data": json.dumps({"value": value}),
                    "time": time.time()
                })
                sendMessage(message, self.hash_to_port[i])

    def validator_select(self):
        """
        This function will select a random node weighted by their balance of UtilityTokens
        :return: hash of selected node
        """
        weightList = list(self.walletList.values())
        hashList = list(self.walletList.keys())
        # Return random weighted choice of node following PoS style
        return random.choices(hashList, weights=weightList, k=1)[0]

    def run(self):
        self.listen()

def sendMessage(message, destPort):
    """
    This function sends a given message to a given port

    :param message: The string message to send
    :param destPort: The port of the destination node
    """
    # establish connection to port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((g.BASE_HOST, destPort))

    # print(f"before encryption: {message}")

    # encrypt the message
    message = crypt.encrypt(message, destPort)

    # print(f"after encryption: {message}")

    # send all bytes of the message
    s.sendall(message)

    # close connection
    s.close()


def main():
    Server(g.BASE_HOST, g.BASE_PORT)

if __name__ == '__main__':
    """
    This executes the main function only if the module is run directly
    """

    main()
