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

                        # action upon receiving an introduction or introduction response
                        if msgJson['type'] == "intro" or msgJson['type'] == "response":

                            # map sender's hash to its local port and give it a unique identifier
                            if msgData['fromport'] not in g.port_to_hash:
                                sha = hasher.sha256()
                                sha.update(str(time.time()).encode(g.ENCODING))
                                # map sender's hash to its local port
                                g.port_to_hash[msgData['fromport']] = msgJson['from']
                                g.hash_to_port[msgJson['from']] = msgData['fromport']
                                # give it a unique identifier for securing later messages
                                g.identifier_dict[msgJson['from']] = sha.hexdigest()


                            # print(f"received handshake from {msgJson['data']}")

                        # Response algorithms

                        # reaction to introduction
                        if (msgJson['type'] == "intro" or msgJson['type'] == "request") \
                                and msgJson['to'] == self.port:
                            self.respond_intro(msgJson, msgData)
                        # reaction to response
                        elif msgJson['type'] == "response":
                            self.respond_response(msgJson, msgData)
                        # reaction to power ref transmission
                        elif msgJson['type'] == "powerref":
                            self.respond_powerref(msgJson, msgData)
                        # reaction to sensitivity transmission
                        elif msgJson['type'] == "sensitivity" and msgJson['identifier'] == g.identifier_dict[msgJson['from']]:
                            self.respond_sensitivity(msgJson, msgData)
                        elif msgJson['type'] == "addblock":
                            self.respond_addblock(msgJson, msgData)
                        # break to accept new messages
                        break
            finally:
                #connection.shutdown(2)
                connection.close()

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
                "identifier": msgJson['identifier'],
                "from": g.my_hash,
                "to": msgJson['from'],
                "time": time.time()
            }

            # if responding to introduction, include port with blockchain
            if msgJson['type'] == "intro":
                message['data'] = json.dumps({"fromport": self.port,
                                              "lasthash": g.blockchain[-1].hash, "chain": bf.get_blocks()})

                # append new node to list of seen nodes
                if msgJson['from'] not in g.node_list:
                    g.node_list.append(msgData['fromport'])
                    # print(f"node list: {node_list}")

            # if responding to a request, just use the blockchain
            else:
                message['data'] = json.dumps({"lasthash": g.blockchain[-1].hash,
                                              "chain": bf.get_blocks()})
            # finally send the message
            sendMessage(json.dumps(message), int(msgData['fromport']))

        except Exception as e:
            print("could not respond to introduction because", e)
            logging.error(f"port {self.port} could not respond to introduction because {e}")
            # breakpoint()


    def respond_response(self, msgJson, msgData):
        """
        This function is responsible for responding to introduction responses

        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
        :return: None
        """

        loaded_chain = json.loads(msgData['chain'])

        # recognize consensus only on NEW blocks
        if loaded_chain[-1]['index'] > g.consensus_index:

            # increment number of consensus messages received
            g.consensus_count += 1

            # Histogram the votes for the blockchain hash
            if msgData['lasthash'] in g.consensus_dict:
                g.consensus_dict[msgData['lasthash']].append(msgJson['from'])
            # if not in the histogram yet, add them after validating the chain
            elif bf.validate(loaded_chain, msgData['lasthash']):
                # store the chain itself
                g.chain_dict[msgData['lasthash']] = loaded_chain
                # add to histogram
                g.consensus_dict[msgData['lasthash']] = [msgJson['from']]

            # if consensus has timed out or received messages from all nodes
            if (g.consensus_time and (time.time() - g.consensus_time > g.CONSENSUS_TIMEOUT)) \
                    or g.consensus_count == len(g.node_list):
                bf.consensus()
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
            "identifier": msgJson['identifier'],
            "from": msgJson['from'],
            "to": msgJson['to'],
            "value": msgData['power'],
            "time": msgJson['time']
        })

        logging.debug(
            f"Message({g.hash_to_port[msgJson['from']]} - {self.port}): Received power ref from {g.hash_to_port[msgJson['from']]} to {self.port}")

        logging.debug(f"updated transaction at index {msgData['id']}: {g.transaction_tracking[msgData['id']]}")

        for j in g.node_list:  # broadcast to all seen nodes
            try:
                # write sensitivity message
                # this is where sensitivity would be calculated
                message = json.dumps({
                    "type": "sensitivity",
                    "identifier": msgJson['identifier'],
                    "from": g.my_hash,
                    "to": msgJson['from'],
                    "data": json.dumps({"id": msgData['id'], "power": msgData['power'],
                                        "sensitivity": 1, "time": msgData['time']}),
                    "time": time.time()
                })
                logging.debug(
                    f"Message({self.port} - {j}): Sending sensitivity from {self.port} to {g.hash_to_port[msgJson['from']]}")

                # broad cast that you're sending power reference to i
                sendMessage(message, j)
            except Exception as e:
                print(f"Couldn't send power ref because {e}")
                logging.warning(
                    f"Unable to respond to power reference from port {self.port} to port {g.hash_to_port[msgJson['from']]}")


    def respond_sensitivity(self, msgJson, msgData):
        """
        This function is responsible for responding to sensitivity messages

        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
        :return: None
        """

        logging.debug(f"Message({g.hash_to_port[msgJson['from']]} - {self.port}): "
                      f"Received sensitivity from {g.hash_to_port[msgJson['from']]} to {self.port}")

        # clear timeout'd messages
        clearTimeouts()

        # store new tracked message
        if str(msgData['id']) in g.transaction_tracking:
            # check that the response power matches the recorded power
            if g.transaction_tracking[msgData['id']][0]['value'] == msgData['power']:
                g.transaction_tracking[msgData['id']].append({
                    "type": msgJson['type'],
                    "identifier": msgJson['identifier'],
                    "from": msgJson['from'],
                    "to": msgJson['to'],
                    "value": msgData['sensitivity'],
                    "time": msgJson['time']
                })
                # store transactions
                bf.add_transaction(msgData['time'], "power", msgJson['from'], msgJson['to'],
                                   msgData['power'])
                bf.add_transaction(msgData['time'], "sense", msgJson['to'], msgJson['from'],
                                   msgData['sensitivity'])

                for j in g.node_list:  # broadcast to all seen nodes
                    try:
                        # write confirmation message
                        message = json.dumps({
                            "type": "confirm",
                            "identifier": msgJson['identifier'],
                            "from": g.my_hash,
                            "to": msgJson['from'],
                            "data": json.dumps({"id": msgData['id'], "power": msgData['power'],
                                                "sensitivity": msgData['sensitivity'], "time": msgData['time']}),
                            "time": time.time()
                        })
                        # broadcast that you're sending confirmation to i
                        sendMessage(message, j)
                    except Exception as e:
                        logging.warning(
                            f"Unable to respond to sensitivity from port {self.port} to port {g.hash_to_port[msgJson['from']]}")

                # if transactions exceed block size, propose a new block
                if len(g.this_nodes_transactions) >= g.BLOCK_SIZE:
                    logging.debug(f"Proposing new block at port {g.my_port}")

                    for j in g.node_list:  # broadcast to all seen nodes
                        try:
                            # write proposal message including transactions and hash for consensus
                            message = json.dumps({
                                "type": "addblock",
                                "from": g.my_hash,
                                "to": g.port_to_hash[j],
                                "data": json.dumps({"transactions": g.this_nodes_transactions,
                                                    "hash": bf.get_transaction_list_hash()}),
                                "time": time.time()
                            })
                            # broadcast message
                            sendMessage(message, j)
                        except Exception as e:
                            logging.warning(
                                f"Unable to propose block from port {self.port} to port {g.hash_to_port[msgJson['from']]} because {e}")


            else:
                logging.warning(f"Power mismatch at port {g.my_port}")
        else:
            logging.warning(f"{msgData['id']} not found in transaction tracking at port {g.my_port}")


    def respond_addblock(self, msgJson, msgData):
        """
        This function is responsible for responding to addblock messages

        :param msgJson:
        :param msgData:
        :return:
        """

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
        for i in range(1, g.NUM_NODES+1):  # broadcast to connected clients from BASE_PORT+1 to BASE_PORT+NUM_NODES
            if g.BASE_PORT + i != self.my_port:   # don't send to yourself
                try:
                    # send my hash to all existing nodes
                    message = json.dumps({
                        "type": "intro",
                        "identifier": None,
                        "from": g.my_hash,
                        "to": g.BASE_PORT+i,
                        "data": json.dumps({"fromport": self.my_port}),
                        "time": time.time()
                    })
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
            # print(f"node list: {node_list}")
            for j in g.node_list:     # broadcast to all seen nodes
                for i in g.node_conn[str(self.my_port)]["downstream"]:   # send power reference to downstream nodes
                    # failsafe: dont broadcast to yourself
                    if(i != self.my_port):
                        try:

                            # specify default power reference (using 1 for normalization)
                            message_power = 1

                            # Create random hash to use as message index
                            sha = hasher.sha256()
                            sha.update(str(time.time()).encode())

                            # create skeleton of message
                            message_variables = {
                                "type": "powerref",
                                "identifier": g.identifier_dict[g.port_to_hash[i]],
                                "from": g.my_hash,
                                "to": g.port_to_hash[i],
                                "time": time.time()
                            }

                            # copy the skeleton to track with different carried data
                            tracked_message = message_variables

                            # set the tracked simplified message value
                            tracked_message['value'] = message_power

                            # set the tracking id
                            tracking_id = sha.hexdigest()

                            # set the data for the actual message
                            message_variables['data'] = json.dumps({
                                "id": tracking_id,
                                "power": message_power,
                                "time": time.time()})

                            # prepare to track message
                            g.transaction_tracking[tracking_id] = []

                            # clear timeout'd messages (if any)
                            clearTimeouts()

                            # store new tracked message
                            g.transaction_tracking[tracking_id].append(tracked_message)

                            # Create secure message
                            message = json.dumps(message_variables)
                            logging.debug(f"Message({self.my_port} - {j}): power ref from {self.my_port} to {i}")

                            # broad cast that you're sending power reference to i
                            sendMessage(message, j)
                        except Exception as e:
                            logging.warning(f"Unable to send power reference broadcast from port {self.my_port} to port {i} because {e}")


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
