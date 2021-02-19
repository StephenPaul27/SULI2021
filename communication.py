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

                            # map sender's hash to its local port
                            g.port_to_hash[msgData['fromport']] = msgJson['from']
                            g.hash_to_port[msgJson['from']] = msgData['fromport']

                            # print(f"received handshake from {msgJson['data']}")

                        # Response algorithm
                        if (msgJson['type'] == "intro" or msgJson['type'] == "request") \
                                and msgJson['to'] == self.port:

                            # respond with port and blockchain for consensus
                            try:
                                message = {
                                    "type": "response",
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

                            # reaction to response
                        elif msgJson['type'] == "response":
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
                                if (g.consensus_time and (time.time() - g.consensus_time > g.CONSENSUS_TIMEOUT))\
                                        or g.consensus_count == len(g.node_list):
                                    bf.consensus()
                                elif not g.consensus_time:
                                    #print("STARTING CONSENSUS TIMER")
                                    # Start recording time since consensus began
                                    g.consensus_time = time.time()

                        # reaction to power ref transmission
                        elif msgJson['type'] == "powerref":
                            for j in g.node_list:  # broadcast to all seen nodes
                                # for i in g.node_conn[str(self.my_port)]["upstream"]:  # send power reference to downstream nodes
                                    # failsafe: dont broadcast to yourself
                                    if (i != self.my_port):
                                        try:
                                            message = json.dumps({
                                                "type": "powerref",
                                                "from": g.my_hash,
                                                "to": msgJson['from'],
                                                "data": json.dumps({"kW": 32.56}),
                                                "time": time.time()
                                            })
                                            logging.debug(
                                                f"Message({self.my_port} - {j}): power ref from {self.my_port} to {i}")
                                            # broad cast that you're sending power reference to i
                                            sendMessage(message, j)
                                        except Exception as e:
                                            logging.warning(
                                                f"Unable to send power reference from port {self.my_port} to port {j}")

                        # break to accept new messages
                        break
            finally:
                #connection.shutdown(2)
                connection.close()

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
        for i in range(0, g.NUM_NODES):  # broadcast to connected clients from 8080 to 80XX
            if g.BASE_PORT + i != self.my_port:   # don't send to yourself
                try:
                    # send my hash to all existing nodes
                    message = json.dumps({
                        "type": "intro",
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
                            message = json.dumps({
                                "type": "powerref",
                                "from": g.my_hash,
                                "to": g.port_to_hash[i],
                                "data": json.dumps({"kW": 32.56}),
                                "time": time.time()
                            })
                            logging.debug(f"Message({self.my_port} - {j}): power ref from {self.my_port} to {i}")
                            # broad cast that you're sending power reference to i
                            sendMessage(message, j)
                        except Exception as e:
                            logging.warning(f"Unable to send power reference from port {self.my_port} to port {j}")


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