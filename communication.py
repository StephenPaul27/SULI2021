"""
This file contains classes and functions relative to sockets enabling communication between blockchain nodes
Every node will have a server for receiving and reacting to messages, and a client for actively sending messages out
"""

# imports
from all_imports import *


class Receiver(threading.Thread):
    """
    This class is responsible for receiving and reacting to messages from other nodes
    """

    def __init__(self, my_host, my_port):
        threading.Thread.__init__(self, name="messenger_receiver")
        self.host = my_host
        self.port = my_port

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
                        # print(f"received a message {time.time()}")
                        # print("\nreceived encrypted message:",full_message)

                        # decrypt received message using known key:
                        full_message = crypt.decrypt(full_message)

                        # print("\ndecrypted message:", full_message)

                        try:
                            # load the message structure as a json
                            msgJson = json.loads(full_message)

                        # Exception catch from message conversion to json
                        except json.JSONDecodeError as e:
                            print(f"Error decoding received message at port {g.my_port}: {e}")
                            logging.error(f"Error decoding received message at port {self.port}: {e}")
                            break

                        # load the data structure that the message is carrying
                        msgData = msgJson['data']
                        # print("msgJson", msgJson)

                        # action upon receiving an introduction or introduction response
                        if msgJson['type'] == "intro" or msgJson['type'] == "response":

                            # map sender's hash to its local port
                            if msgData['fromport'] not in g.port_to_hash:
                                sha = hasher.sha256()
                                sha.update(str(time.time()).encode(g.ENCODING))
                                # map sender's hash to its local port
                                g.port_to_hash[msgData['fromport']] = msgJson['from']
                                g.hash_to_port[msgJson['from']] = msgData['fromport']

                            # in response from smartcontract, the validators are included
                            if msgJson['from'] == g.port_to_hash[g.BASE_PORT]\
                                    and "validators" in msgData:
                                g.validator_list = msgData['validators']
                                logging.debug("Validators updated from introduction")


                            # print(f"received handshake from {msgJson['data']}")

                        # Response algorithms

                        # reaction to introduction
                        if (msgJson['type'] == "intro" or msgJson['type'] == "request") \
                                and msgJson['to'] == self.port:
                            self.respond_intro(msgJson, msgData)
                        # reaction to response
                        elif msgJson['type'] == "response" and 'lasthash' in msgData:
                            self.respond_response(msgJson, msgData)
                        # reaction to power ref transmission
                        elif msgJson['type'] == "powerref":
                            self.respond_powerref(msgJson, msgData)
                        # reaction to sensitivity transmission
                        elif msgJson['type'] == "sensitivity":
                            self.respond_sensitivity(msgJson, msgData)
                        elif msgJson['type'] == "confirm":
                            self.respond_confirm(msgJson, msgData)
                        elif msgJson['type'] == "request" and msgJson['from'] in g.validator_list:
                            self.respond_request(msgJson, msgData)
                        elif msgJson['type'] == "addblock":
                            self.respond_addblock(msgJson, msgData)
                        elif msgJson['type'] == 'validators':
                            self.respond_validators(msgJson, msgData)
                        elif msgJson['type'] == 'payment':
                            self.respond_pay(msgJson, msgData)
                        # break to accept new messages
                        break
            finally:
                #connection.shutdown(2)
                connection.close()


    def respond_validators(self, msgJson, msgData):
        """
        This function is responsible for recording validators from the smartcontract

        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
        :return: None
        """
        if msgJson['from'] == g.port_to_hash[g.BASE_PORT]:
            g.validator_list = []
            for i in msgData['validators']:
                g.validator_list.append(i)


    def respond_intro(self, msgJson, msgData):
        """
        This function is responsible for responding to the introduction message of a new node

        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
        :return: None
        """

        # respond with port and blockchain for consensus
        try:
            message = {
                "type": "response",
                "from": g.my_hash,
                "to": msgJson['from'],
                "data": {
                            "fromport": self.port,
                            "lasthash": g.blockchain[-1].hash,
                            "chain": bf.get_dict_list(),
                            "transactions": bf.get_dict_list(chainList=g.this_nodes_transactions)
                        },
                "time": time.time()
            }

            # append new node to list of seen nodes
            if msgJson['from'] not in g.node_list:
                g.node_list.append(msgData['fromport'])
                # print(f"node list: {node_list}")
            # finally send the message
            sendMessage(message, int(msgData['fromport']))

        except Exception as e:
            print("could not respond to introduction because", e)
            logging.error(f"port {self.port} could not respond to introduction because {e}")
            # breakpoint()

    def respond_request(self, msgJson, msgData):
        """
        This function will respond to requests for the blockchain

        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
        :return: None
        """

        # if ready to add a new block, go ahead and put it on your blockchain
        if len(g.this_nodes_transactions) >= g.BLOCK_SIZE\
                and g.blockchain[-1].index < msgData['index']:
            bf.add_trans_to_block()

        # respond with port and blockchain for consensus
        try:
            message = {
                "type": "addblock",
                "from": g.my_hash,
                "to": msgJson['from'],
                "data": {
                            "lasthash": g.blockchain[-1].hash,
                            "chain": bf.get_dict_list(),
                            "transactions": bf.get_dict_list(chainList=g.this_nodes_transactions)
                        },
                "time": time.time()
            }

            # finally send the message
            sendMessage(message, g.hash_to_port[msgJson['from']])

        except Exception as e:
            print("could not respond to request because", e)
            logging.error(f"port {self.port} could not respond to request because {traceback.format_exc()}")
            # breakpoint()

    def respond_response(self, msgJson, msgData):
        """
        This function is responsible for responding to introduction responses

        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
        :return: None
        """

        # only accept one vote per consensus
        if msgJson['from'] not in g.consensus_id_list:
            g.consensus_id_list.append(msgJson['from'])
        else:
            return

        # recognize consensus only on NEW blocks
        if len(msgData['chain']) and msgData['chain'][-1]['index'] > g.consensus_index:
            loaded_transactions = bf.get_trans_objs(msgData['transactions'])
            T_hash = bf.get_transaction_list_hash(loaded_transactions)
            # create combination hash of transactions and blockchain
            comboHash = bf.get_hash(str(msgData['lasthash'])+str(T_hash))

            # Histogram the votes for the blockchain hash
            if comboHash in g.consensus_dict:
                g.consensus_dict[comboHash].append(msgJson['from'])
            # if not in the histogram yet, add them after validating the chain
            elif bf.validate(msgData['chain'], msgData['lasthash']):
                # store the chain itself
                g.chain_dict[comboHash] = msgData['chain']
                g.trans_dict[comboHash] = loaded_transactions
                # add to histogram
                g.consensus_dict[comboHash] = [msgJson['from']]

            # if consensus has timed out or received messages from all participating nodes
            if (g.consensus_time and (time.time() - g.consensus_time > g.CONSENSUS_TIMEOUT)) \
                    or len(g.consensus_id_list) == len(g.node_list)-1:
                # perform consensus
                g.blockchain, g.this_nodes_transactions = bf.consensus()
                # reset the consensus variables and set the updated consensus-agreed index
                bf.reset_consensus(g.blockchain[-1].index)
            elif not g.consensus_time:
                # print("STARTING CONSENSUS TIMER")
                # Start recording time since consensus began
                g.consensus_time = time.time()

    def respond_powerref(self, msgJson, msgData):
        """
        This function is responsible for responding to power reference messages

        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
        :return: None
        """

        # for i in g.node_conn[str(self.my_port)]["upstream"]:  # send power reference to downstream nodes

        # clear tracked message
        g.transaction_tracking[msgData['id']] = []

        # clear timeout'd messages
        clearTimeouts()

        # store new tracked message
        g.transaction_tracking[msgData['id']].append({
            "type": msgJson['type'],
            "from": msgJson['from'],
            "to": msgJson['to'],
            "value": msgData['power'],
            "time": msgJson['time']
        })

        logging.debug(
            f"Message({g.hash_to_port[msgJson['from']]} - {self.port}): Received power ref from "
            f"{g.hash_to_port[msgJson['from']]} to {g.hash_to_port[msgJson['to']]}")

        logging.debug(f"updated transaction at index {msgData['id']}: {g.transaction_tracking[msgData['id']]}")

        for j in g.node_list:  # broadcast to all seen nodes
            try:
                # write sensitivity message
                # this is where sensitivity would be calculated
                message = {
                    "type": "sensitivity",
                    "from": g.my_hash,
                    "to": msgJson['from'],
                    "data": {
                                "id": msgData['id'],
                                "power": msgData['power'],
                                "sensitivity": 1,
                                "time": msgData['time']
                            },
                    "time": time.time()
                }
                logging.debug(
                    f"Message({self.port} - {j}): Sending sensitivity from {self.port} to {g.hash_to_port[msgJson['from']]}")

                # broad cast that you're sending power reference to i
                sendMessage(message, j)
            except Exception as e:
                print(f"Couldn't send power ref because {e}")
                logging.warning(
                    f"Unable to respond to power reference from port {self.port} to port {g.hash_to_port[msgJson['from']]} because {e}")

    def respond_sensitivity(self, msgJson, msgData):
        """
        This function is responsible for responding to sensitivity messages

        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
        :return: None
        """

        logging.debug(f"Message({g.hash_to_port[msgJson['from']]} - {self.port}): "
                      f"Received sensitivity from {g.hash_to_port[msgJson['from']]} to {g.hash_to_port[msgJson['from']]}")

        # clear timeout'd messages
        clearTimeouts()

        # store new tracked message
        if str(msgData['id']) in g.transaction_tracking:
            # check that the response power matches the tracked power variables
            if g.transaction_tracking[msgData['id']][0]['value'] == msgData['power']\
                    and g.transaction_tracking[msgData['id']][0]['from'] == msgJson['to']:
                g.transaction_tracking[msgData['id']].append({
                    "type": msgJson['type'],
                    "from": msgJson['from'],
                    "to": msgJson['to'],
                    "value": msgData['sensitivity'],
                    "time": msgJson['time']
                })

                logging.debug(f"updated transaction at index {msgData['id']}: {g.transaction_tracking[msgData['id']]}")

                # if receiving the sensitivity consider it confirmed
                if msgJson['to'] == g.my_hash:
                    # store transactions
                    g.this_nodes_transactions = bf.add_transaction(msgData['time'], "power", msgJson['to'], msgJson['from'],
                                       msgData['power'])
                    g.this_nodes_transactions = bf.add_transaction(msgData['time'], "sense", msgJson['from'], msgJson['to'],
                                       msgData['sensitivity'])
                    # write to local storage
                    ne.update_transactions()

                    for j in g.node_list:  # broadcast confirmation to all seen nodes
                        try:
                            # write confirmation message
                            message = {
                                "type": "confirm",
                                "from": g.my_hash,
                                "to": msgJson['from'],
                                "data": {
                                            "id": msgData['id'],
                                            "power": msgData['power'],
                                            "sensitivity": msgData['sensitivity'],
                                            "time": msgData['time']
                                        },
                                "time": time.time()
                            }

                            logging.debug(f"Message({self.port} - {j}): "
                                          f"Sending Confirmation from {self.port} to {g.hash_to_port[msgJson['from']]}")
                            # broadcast that you're sending confirmation to i
                            sendMessage(message, j)
                        except Exception as e:
                            logging.warning(
                                f"Unable to respond to sensitivity from port {self.port} to port {g.hash_to_port[msgJson['from']]}")

                    # if transactions exceed block size and this node is a validator, propose a new block
                    if len(g.this_nodes_transactions) >= g.BLOCK_SIZE and g.my_hash in g.validator_list:
                        logging.debug(f"Proposing new block at port {g.my_port}")
                        self.propose_block(msgJson, msgData)



            else:
                logging.warning(f"Power mismatch at port {g.my_port}")
        else:
            logging.warning(f"{msgData['id']} not found in transaction tracking at port {g.my_port}")

    def propose_block(self, msgJson, msgData):
        """
        This function will propose a block update to all of the other blocks
        :return: None
        """

        # if ready to add a new block, go ahead and put it on your blockchain
        if len(g.this_nodes_transactions) >= g.BLOCK_SIZE:
            bf.add_trans_to_block()

        for j in g.node_list:  # broadcast to all seen nodes
            try:
                # write proposal message including transactions and hash for consensus
                message = {
                    "type": "request",
                    "from": g.my_hash,
                    "to": g.port_to_hash[j],
                    "data": {
                                "transactions": bf.get_dict_list(g.this_nodes_transactions),
                                "hash": bf.get_transaction_list_hash(),
                                "index": g.blockchain[-1].index
                            },
                    "time": time.time()
                }
                # broadcast message
                sendMessage(message, j)
            except Exception as e:
                logging.warning(
                    f"Unable to propose block from port {self.port} to port {g.hash_to_port[msgJson['from']]} because {e}")

    def respond_confirm(self, msgJson, msgData):
        """
        This function will add the power/sensitivity transaction to the transaction list of this node
        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
        :return: None
        """

        logging.debug(f"Message({g.hash_to_port[msgJson['from']]} - {self.port}): "
                      f"Received confirmation from {g.hash_to_port[msgJson['from']]} to {g.hash_to_port[msgJson['to']]}")

        # store transactions
        g.this_nodes_transactions = bf.add_transaction(msgData['time'], "power", msgJson['from'], msgJson['to'],
                                                       msgData['power'])
        g.this_nodes_transactions = bf.add_transaction(msgData['time'], "sense", msgJson['to'], msgJson['from'],
                                                       msgData['sensitivity'])
        # write to local storage
        ne.update_transactions()

        # if transactions exceed block size and this node is a validator, propose a new block
        if len(g.this_nodes_transactions) >= g.BLOCK_SIZE and g.my_hash in g.validator_list:
            logging.debug(f"Proposing new block at port {g.my_port}")
            self.propose_block(msgJson, msgData)

    def respond_addblock(self, msgJson, msgData):
        """
        This function will perform consensus on addblock messages received from other nodes
        then it will send the result to the smartcontract to finalize

        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
        :return: None
        """

        # only accept one vote per consensus
        if msgJson['from'] not in g.consensus_id_list:
            g.consensus_id_list.append(msgJson['from'])
        else:
            return

        # recognize consensus only on NEW blocks
        if len(msgData['chain']) and msgData['chain'][-1]['index'] > g.consensus_index:
            loaded_transactions = bf.get_trans_objs(msgData['transactions'])
            T_hash = bf.get_transaction_list_hash(loaded_transactions)
            # create combination hash of transactions and blockchain
            comboHash = bf.get_hash(str(msgData['lasthash']) + str(T_hash))

            # Histogram the votes for the blockchain hash
            if comboHash in g.consensus_dict:
                g.consensus_dict[comboHash].append(msgJson['from'])
            # if not in the histogram yet, add them after validating the chain
            elif bf.validate(msgData['chain'], msgData['lasthash']):
                # store the chain itself
                g.chain_dict[comboHash] = msgData['chain']
                g.trans_dict[comboHash] = loaded_transactions
                # add to histogram
                g.consensus_dict[comboHash] = [msgJson['from']]

            # if consensus has timed out or received messages from all participating nodes
            if (g.consensus_time and (time.time() - g.consensus_time > g.CONSENSUS_TIMEOUT)) \
                    or len(g.consensus_id_list) == len(g.node_list) - 1:
                # perform consensus
                g.blockchain, g.this_nodes_transactions = bf.consensus()

                # send consensus result to the smart contract
                try:
                    message = {
                        "type": "consensus",
                        "from": g.my_hash,
                        "to": g.port_to_hash[g.BASE_PORT],
                        "data": {
                                    "lasthash": g.blockchain[-1].hash,
                                    "chain": bf.get_dict_list(),
                                    "transactions": bf.get_dict_list(chainList=g.this_nodes_transactions)
                                },
                        "time": time.time()
                    }
                    sendMessage(message, g.BASE_PORT)
                except Exception as e:
                    logging.warning(f"Couldn't send chain from {g.my_port} to smart contract because {e}")

                # reset the consensus variables and set the updated consensus-agreed index
                bf.reset_consensus(g.blockchain[-1].index)
            elif not g.consensus_time:
                # print("STARTING CONSENSUS TIMER")
                # Start recording time since consensus began
                g.consensus_time = time.time()

    def respond_pay(self, msgJson, msgData):
        """
        This method will automatically insort payment transactions from the smartcontract

        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
        :return: None
        """

        if msgJson['from'] == g.port_to_hash[g.BASE_PORT]:
            g.this_nodes_transactions = bf.add_transaction(msgJson['time'], "payment", msgJson['from'], msgJson['to'],
                                                           msgData['value'])
            # correct our blockchain if it doesnt match the agreed one
            if msgData['lasthash'] != g.blockchain[-1].hash:
                g.blockchain = bf.get_block_objs(msgData['chain'])
            ne.update_transactions()

            # if transactions exceed block size and this node is a validator, propose a new block
            if len(g.this_nodes_transactions) >= g.BLOCK_SIZE and g.my_hash in g.validator_list:
                logging.debug(f"Proposing new block at port {g.my_port}")
                self.propose_block(msgJson, msgData)
        else:
            logging.warning(f"Attempted payment observed at {g.my_port} from {g.hash_to_port[msgJson['from']]}")

    def run(self):
        self.listen()


class Sender(threading.Thread):
    """
    This class is responsible for actively sending data including power references and introduction
    """
    def __init__(self, my_host, my_port):
        threading.Thread.__init__(self, name="messenger_sender")
        self.my_host = my_host
        self.my_port = my_port

    def run(self):

        # Introduce yourself on the first run
        for i in range(0, g.NUM_NODES+1):  # broadcast to connected clients from BASE_PORT+1 to BASE_PORT+NUM_NODES
            if g.BASE_PORT + i != self.my_port:   # don't send to yourself
                try:
                    # send my hash to all existing nodes
                    message = {
                        "type": "intro",
                        "from": g.my_hash,
                        "to": g.BASE_PORT+i,
                        "data": {"fromport": self.my_port},
                        "time": time.time()
                    }
                    sendMessage(message, g.BASE_PORT + i)

                    # track active ports/nodes that successfully connected
                    g.node_list.append(g.BASE_PORT+i)

                except Exception as e:
                    print(f"no connection detected at {g.BASE_PORT+i} because {e}")
                    do_nothing = True

        while True:
            # broadcast every MSG_PERIOD seconds
            time.sleep(g.MSG_PERIOD)
            # breakpoint()
            # print(f"sending powerrefs {time.time()}")

            for i in g.node_conn[str(self.my_port)]["downstream"]:   # send power reference to downstream nodes

                # specify default power reference (using 1 for normalization)
                message_power = 1

                for j in g.node_list:  # broadcast to all seen nodes
                    # failsafe: dont broadcast to yourself
                    if(i != self.my_port and j != self.my_port):
                        try:

                            # Create random hash to use as message index
                            sha = hasher.sha256()
                            sha.update(str(time.time()).encode())

                            # create skeleton of message
                            message = {
                                "type": "powerref",
                                "from": g.my_hash,
                                "to": g.port_to_hash[i],
                                "time": time.time()
                            }

                            # copy the skeleton to track with different carried data
                            tracked_message = message

                            # set the tracked simplified message value
                            tracked_message['value'] = message_power

                            # set the tracking id
                            tracking_id = sha.hexdigest()

                            # set the data for the actual message
                            message['data'] = {
                                "id": tracking_id,
                                "power": message_power,
                                "time": time.time()
                            }

                            # prepare to track message
                            g.transaction_tracking[tracking_id] = []

                            # clear timeout'd messages (if any)
                            clearTimeouts()

                            # store new tracked message
                            g.transaction_tracking[tracking_id].append(tracked_message)

                            logging.debug(f"Message({self.my_port} - {j}): Sending power ref from {self.my_port} to {i}")

                            # broad cast that you're sending power reference to i
                            sendMessage(message, j)
                        except Exception as e:
                            logging.warning(f"Unable to send power reference broadcast from port {self.my_port} to port {i} because {e}")


def sendMessage(message, destPort, pr_key=None):
    """
    This function sends a given message to a given port

    :param pr_key: private key (None defaults to global variable)
    :param message: The string message to send
    :param destPort: The port of the destination node
    """

    try:
        message = json.dumps(message)
    except json.JSONDecodeError:
        print(f"Message failed to send to port {destPort} because it couldn't be json formatted")
        logging.error(f"Message failed to send to port {destPort} because it couldn't be json formatted: {traceback.format_exc()}")

    # print(f"sending message to port{destPort}")

    # establish connection to port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((g.BASE_HOST, destPort))

    # print(f"before encryption: {message}")

    # encrypt the message
    message = crypt.encrypt(message, destPort, pr_key)

    # print(f"after encryption: {message}")

    # send all bytes of the message
    s.sendall(message)

    # close connection
    s.close()

def clearTimeouts():
    """
    This function will clear message entries in the transaction tracking record if they have exceeded the timeout

    :return: None
    """

    timeNow = time.time()
    # pop any message records that have an age exceeding the timeout
    for i in list(g.transaction_tracking):
        if len(g.transaction_tracking[i]) and timeNow-g.transaction_tracking[i][0]['time'] > g.MSG_TIMEOUT:
            g.transaction_tracking.pop(i)
