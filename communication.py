"""
This file contains classes and functions relative to sockets enabling communication between blockchain nodes
Every node will have a server for receiving and reacting to messages, and a client for actively sending messages out
"""

# imports
from all_imports import *

"""
This class is responsible for receiving and reacting to messages from other nodes
"""
class Receiver(threading.Thread):

    def __init__(self, my_host, my_port):
        threading.Thread.__init__(self, name="messenger_receiver")
        self.host = my_host
        self.port = my_port

    def listen(self):

        global blockchain
        global NUM_NODES
        global ENCODING

        # create server socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(NUM_NODES)
        # print("server started")

        # while loop to accept incoming connections/messages
        while True:

            # accept client connection
            connection, client_address = sock.accept()
            # print(connection)

            try:
                full_message = ""

                # while loop to read in data from incoming message
                while True:

                    data = connection.recv(1024)
                    full_message = full_message + data.decode(ENCODING)
                    # print(data.decode(ENCODING))

                    # once data has stopped coming in, decode the message
                    if not data:

                        #print("received a message: ", full_message)

                        try:
                            # load the message structure
                            msgJson = json.loads(full_message)

                            # load the data structure that the message is carrying
                            msgData = json.loads(msgJson['data'])
                            # print("msgJson", msgJson)
                        # Exception catch from message conversion to json
                        except Exception as e:
                            print(f"Error decoding received message: {e}")
                            break
                        # action upon handshake
                        if msgJson['type'] == "intro" or msgJson['type'] == "response":

                            # map sender's hash to its local port
                            port_to_hash[msgData['fromport']] = msgJson['from']
                            hash_to_port[msgJson['from']] = msgData['fromport']

                            # print(f"received handshake from {msgJson['data']}")

                        # Response algorithm
                        if (msgJson['type'] == "intro" or msgJson['type'] == "request") \
                                and msgJson['to'] == self.port:
                            # print(f"current blockchain: {blockchain}")
                            # respond with port and blockchain for consensus
                            try:
                                message = {
                                    "type": "response",
                                    "from": my_hash,
                                    "to": msgJson['from'],
                                    "time": time.time()
                                }
                                if msgJson['type'] == "intro":
                                    message['data'] = json.dumps({"fromport": self.port,
                                          "lasthash": blockchain[-1].hash, "chain": bf.get_blocks()})
                                    # append new node to list of nodes
                                    if msgJson['from'] not in node_list:
                                        node_list.append(msgData['fromport'])
                                        # print(f"node list: {node_list}")
                                else:
                                    message['data'] = json.dumps({"lasthash": blockchain[-1].hash,
                                                                  "chain": bf.get_blocks()})
                                sendMessage(json.dumps(message), int(msgData['fromport']))
                            except Exception as e:
                                print("could not respond to introduction because ", e)
                                # breakpoint()

                            # reaction to response
                        elif msgJson['type'] == "response":
                            global consensus_dict
                            global consensus_time
                            global consensus_count
                            global chain_dict
                            loaded_chain = json.loads(msgData['chain'])
                            # recognize consensus only on NEW blocks

                            if loaded_chain[-1]['index'] > consensus_index:

                                consensus_count += 1    #increment number of consensus messages received

                                # Histogram the votes for the blockchain hash
                                if msgData['lasthash'] in consensus_dict:
                                    consensus_dict[msgData['lasthash']].append(msgJson['from'])
                                # if not in the histogram yet, add them after validating the chain
                                elif bf.validate(loaded_chain, msgData['lasthash']):
                                    # store the chain itself
                                    chain_dict[msgData['lasthash']] = loaded_chain
                                    # add to histogram
                                    consensus_dict[msgData['lasthash']] = [msgJson['from']]

                                # if consensus has timed out or received messages from all nodes
                                if (consensus_time and (time.time() - consensus_time > CONSENSUS_TIMEOUT))\
                                        or consensus_count == len(node_list):
                                    bf.consensus()
                                elif not consensus_time:
                                    #print("STARTING CONSENSUS TIMER")
                                    # Start recording time since consensus began
                                    consensus_time = time.time()

                        # reaction to power ref transmission
                        elif msgJson['type'] == "powerref":
                            print(f"type: {msgJson['type']}\n"
                                  f"from: {msgJson['from']}\n"
                                  f"to: {msgJson['to']}\n"
                                  f"data: {msgJson['data']}\n"
                                  f"time: {msgJson['time']}\n")

                        break
            finally:
                #connection.shutdown(2)
                connection.close()

    def run(self):
        self.listen()


"""
This class is responsible for actively sending data including power references and introduction
"""
class Sender(threading.Thread):

    def __init__(self, my_host, my_port):
        threading.Thread.__init__(self, name="messenger_sender")
        # self.host = my_friends_host
        # self.port = my_friends_port
        self.my_host = my_host
        self.my_port = my_port

    def run(self):

        # Introduce yourself on the first run
        for i in range(0, NUM_NODES):  # broadcast to connected clients from 8080 to 80XX
            if BASE_PORT + i != self.my_port:   # don't send to yourself
                try:
                    # send my hash to all existing nodes
                    message = json.dumps({
                        "type": "intro",
                        "from": my_hash,
                        "to": BASE_PORT + i,
                        "data": json.dumps({"fromport": self.my_port}),
                        "time": time.time()
                    })
                    sendMessage(message, BASE_PORT + i)

                    # track ports/nodes that successfully connected
                    node_list.append(BASE_PORT+i)
                except Exception as e:
                    print(f"no connection detected at {BASE_PORT+i}")

        while True:
            time.sleep(MSG_PERIOD)      # sleep X seconds before each broadcast
            # breakpoint()
            # print(f"node list: {node_list}")
            for i in node_list:   # broadcast to connected clients in node list
                if(i != self.my_port):
                    try:
                        message = json.dumps({
                            "type": "powerref",
                            "from": my_hash,
                            "to": port_to_hash[i],
                            "data": 32.56,
                            "time": time.time()
                        })
                        sendMessage(message, i)
                    except Exception as e:
                        do_nothing = True

"""
This function sends a given message to a given port
"""
def sendMessage(message, destPort):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((BASE_HOST, destPort))

    s.sendall(str(message).encode(ENCODING))

    # s.shutdown(2)
    s.close()