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
        """
        This function will initialize the receiver server variables
        :param my_host: host of this node
        :param my_port: port of this node
        """
        threading.Thread.__init__(self, name="messenger_receiver")
        self.host = my_host
        self.port = my_port

    def run(self):
        self.listen()

    def listen(self):
        """
        This function is the listener for incoming messages
        """

        # create server socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(g.SOCKET_CONNECTIONS)
        # print("server started")

        # while loop to accept incoming connections/messages
        while True:
            try:

                # accept client connection
                connection, client_address = sock.accept()
                # print(connection)

                try:
                    # initialize message 'string'
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

                            # go ahead and close the connection
                            if connection.fileno() != -1:
                                connection.close()

                            # print(f"received a message {time.time()}")
                            # print("\nreceived encrypted message:",full_message)

                            # decrypt received message using known keys:
                            full_message = crypt.decrypt(full_message)

                            if not full_message or full_message == "ERROR":
                                logging.warning(f"Node {g.my_port} decryption failed")
                                break

                            # print("\ndecrypted message:", full_message)

                            try:
                                # load the message structure as a json
                                msgJson = json.loads(full_message)

                            # Exception catch if for some reason the json conversion fails
                            except json.JSONDecodeError as e:
                                print(f"Error decoding received message at port {g.my_port}: {e}")
                                logging.error(f"Error decoding received message at port {self.port}: {e}")
                                break

                            # load the data structure that the message is carrying
                            msgData = msgJson['data']
                            # print("msgJson", msgJson)

                            # action upon receiving an introduction or introduction response
                            if msgJson['type'] == "intro" or msgJson['type'] == "response":

                                # map sender's hash to its provided port
                                if msgData['fromport'] not in g.port_to_hash:
                                    # map sender's hash to its local port and vice versa
                                    g.port_to_hash[msgData['fromport']] = msgJson['from']
                                    g.hash_to_port[msgJson['from']] = msgData['fromport']

                                    # update node connections just in case this node added one
                                    with open("Storage/node_connections_fork.json", 'r') as f:
                                        node_conn = json.load(f)

                                # in response from smartcontract, the validators are included
                                if "validators" in msgData and msgJson['from'] == g.port_to_hash[g.BASE_PORT]:
                                    g.validator_list = msgData['validators']
                                    logging.debug(f"Validators updated at node {g.my_port} from introduction")

                                # print(f"received handshake from {msgJson['data']}")

                            # Response algorithms

                            # reactions to different message types
                            if (msgJson['type'] == "intro" or msgJson['type'] == "request") \
                                    and msgJson['to'] == self.port:
                                self.respond_intro(msgJson, msgData)
                            elif msgJson['type'] == "response" and 'lasthash' in msgData:
                                self.respond_response(msgJson, msgData)
                            elif msgJson['type'] == "powerref":
                                self.respond_powerref(msgJson, msgData)
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
                            elif msgJson['type'] == 'powerDMPC':
                                self.respond_powerDMPC(msgJson, msgData)
                            elif msgJson['type'] == 'powerRequest':
                                self.respond_powerRequest(msgJson, msgData)
                            elif msgJson['type'] == 'powerResponse':
                                self.respond_powerResponse(msgJson,msgData)

                            # break to accept new messages
                            break
                # close the connection on the server side
                finally:
                    #connection.shutdown(2)
                    # if not closed already:
                    if connection.fileno() != -1:
                        connection.close()
            except:
                logging.error(f"Node {g.my_port} failed because {traceback.format_exc()}, restarting...")
                print(f"Node {g.my_port} failed because {traceback.format_exc()}")

    def respond_powerDMPC(self, msgJson, msgData):
        if g.DMPC_SIM:
            g.my_power = msgData['value']
            # send power if not in traitor ports
            if g.my_port not in g.TRAITOR_PORTS:
                sendPowerref(msgData['value'])

                # start timer thread for each upstream node
                for i in [x for x in g.node_conn[str(g.my_port)]['upstream'] if x in g.node_list]:
                    # Check that it hasn't sent a power ref in the last g.MSG_TIMEOUT seconds
                    if i not in [g.hash_to_port[x.sender] for x in g.this_nodes_transactions
                          if ((time.time()-x.timestamp) <= g.MSG_TIMEOUT
                              and x.type == "power")]:

                        g.power_thread[int(i)] = tmo.Timeout("request_power", self.request_power,
                                                                              g.MSG_TIMEOUT, threadNum=int(i))
                        g.power_thread[int(i)].start()

    def respond_validators(self, msgJson, msgData):
        """
        This function is responsible for recording validators broadcasted from the smartcontract

        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
        """
        if msgJson['from'] == g.port_to_hash[g.BASE_PORT]:
            logging.debug(f"Updating validators at node {g.my_port} from broadcast, me?:{g.my_hash in msgData['validators']}")
            g.validator_list = msgData['validators']

    def respond_intro(self, msgJson, msgData):
        """
        This function is responsible for responding to the introduction message of a new node

        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
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
            if msgData['fromport'] not in g.node_list and msgData['fromport'] != g.BASE_PORT:
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
        """

        logging.debug(f"Node {g.my_port} received request from {g.hash_to_port[msgJson['from']]} "
                      f"for {msgData['index']}, This node has idx: {g.blockchain[-1].index} and cindex of {g.consensus_index}")

        if msgJson['from'] not in g.validator_list:
            logging.warning(f"Node {g.my_port} received non-validator request from {g.hash_to_port[msgJson['from']]}")
            return

        if g.my_port in g.TRAITOR_PORTS:
            do_nothing = True
            # idx = random.choices([-1, 0], weights=[80, 20], k=1)[0]
            # if not idx:
            #     logging.warning(f"Traitor {g.my_port} is doing its interfering (request)")
            #     # send a different block
            #     # g.blockchain[-1] = create_genesis_block(g.blockchain[-1].previous_hash)
            #     # idx = -1
            #     return  # cause timeout error

        # if ready to add a new block, go ahead and put it on your blockchain
        if len(g.this_nodes_transactions) >= g.BLOCK_SIZE \
                and g.blockchain[-1].index == msgData['index']-1\
                and g.blockchain[-1].index == g.consensus_index:

            # if transactions exceed block size and this node is a validator, propose a new block
            if len(g.this_nodes_transactions) >= g.PROPOSE_TRIGGER \
                    and g.my_hash in g.validator_list \
                    and g.last_proposed <= g.consensus_index:
                logging.debug(f"Proposing new block at port {g.my_port} from pay")
                propose_block(msgJson, msgData)
            else:
                bf.add_trans_to_block()

        # respond with port and blockchain for consensus
        try:
            message = {
                "type": "addblock",
                "from": g.my_hash,
                "to": msgJson['from'],
                "data": {
                    "lasthash": g.blockchain[-1].hash,
                    "newblock": g.blockchain[-1].to_dict(),
                    "transactions": bf.get_dict_list(chainList=g.this_nodes_transactions)
                },
                "time": time.time()
            }

            # finally send the message
            sendMessage(message, g.hash_to_port[msgJson['from']])

        except Exception as e:
            print("could not respond to request because", e)
            logging.error(f"port {self.port} could not respond to request from port {g.hash_to_port[msgJson['from']]} because {traceback.format_exc()}")
            # breakpoint()

    def respond_response(self, msgJson, msgData):
        """
        This function is responsible for responding to introduction responses
        (performing consensus on all of the returned blockchains)

        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
        """

        # recognize consensus only on NEW blocks
        if msgData['chain'][-1]['index'] > g.consensus_index:

            # only accept one vote per consensus
            if msgJson['from'] not in g.consensus_id_list:
                g.consensus_id_list.append(msgJson['from'])
            else:
                return

            # if len(msgData['chain']) and msgData['chain'][-1]['index'] > g.consensus_index:

            logging.debug(
                f"node {g.my_port} received response from {msgData['fromport']}, {len(g.consensus_id_list)}/{len(g.node_list)}")

            loaded_transactions = bf.get_trans_objs(msgData['transactions'])

            # if hash has already been validated, just add it to the list
            if msgData['lasthash'] in g.consensus_array:
                g.consensus_array.append(msgData['lasthash'])
            # if not in the histogram yet, add them after validating the chain
            elif bf.validate(msgData['chain'], msgData['lasthash'], fromport=g.hash_to_port[msgJson['from']]):
                g.consensus_array.append(msgData['lasthash'])
                # store the chain itself
                g.chain_dict[msgData['lasthash']] = msgData['chain']

            # create list of transaction hashes from the list loaded from the message
            check_duplicates = [i.hash for i in loaded_transactions]

            # if there are no duplicate transactions in the list loaded from the message
            if len(set(check_duplicates)) == len(check_duplicates):
                # go through all of the transactions in the list loaded from the message
                for i in loaded_transactions:
                    # histogram votes for specific transactions
                    try:
                        g.trans_vote_dict[i.hash].append(msgJson['from'])
                    except:
                        # add transaction to histogram if not in it
                        g.trans_vote_dict[i.hash] = [msgJson['from']]
                        g.trans_dict[i.hash] = i

            # start a timeout timer for responses if not already started
            if not g.response_timer_thread:
                logging.debug(f"Response timer STARTED at node {g.my_port}")
                g.response_timer_thread = tmo.Timeout("response", bf.consensus_and_reset, g.CONSENSUS_TIMEOUT,None)
                g.response_timer_thread.start()

            # if consensus has received messages from all participating nodes
            if len(g.consensus_id_list) >= len(g.node_list):
                print(f"performing consensus after {len(g.consensus_id_list)}/{len(g.node_list)} votes")
                logging.debug(f"node {g.my_port} is performing consensus after {len(g.consensus_id_list)}/{len(g.node_list)} ")
                # perform consensus
                bf.consensus_and_reset()
                g.last_proposed = g.blockchain[-1].index

        else:
            logging.warning(f"response received at node {g.my_port} from {msgData['fromport']} index: {msgData['chain'][-1]['index']}>{g.consensus_index}")

    def request_power(self, threadNum):
        """
        This function will request power for consensus in the event that it does not receive power from upstream
        :param port:
        :return:
        """
        # stop the timer for the sending node
        if threadNum in g.power_thread:
            g.power_thread[threadNum].stop()
            g.power_thread.pop(threadNum)

        if threadNum in g.port_to_hash:
            reportNode(g.port_to_hash[threadNum])

        for i in g.node_list:
            message = {
                "type": "powerRequest",
                "from": g.my_hash,
                "to": g.port_to_hash[i],
                "data": {"report":threadNum},
                "time": time.time()
            }
            sendMessage(message,i)

    def respond_powerRequest(self,msgJson, msgData):
        """
        This function responds to a request for power reference
        :param msgJson:
        :param msgData:
        """
        # dont respond if traitor (proper response?)
        if g.my_port != msgData['report'] and g.my_power is not None:
            # collective report the node causing the timeout
            if msgData['report'] in g.port_to_hash:
                reportNode(g.port_to_hash[msgData['report']])

            # respond with my last received power
            message = {
                "type": "powerResponse",
                "from": g.my_hash,
                "to": msgJson['from'],
                "data": {
                    "power": g.my_power,
                    "reported": msgData['report']
                },
                "time": time.time()
            }
            sendMessage(message, g.hash_to_port[msgJson['from']])
        else:
            logging.debug(f"Node {g.my_port} is not responding to {g.hash_to_port[msgJson['from']]}'s power request that reported {msgData['report']}")

    def respond_powerResponse(self, msgJson, msgData):
        """
        This function will do a form of consensus on the powers of other nodes
        :param msgJson:
        :param msgData:
        :return:
        """
        # dont take response from culprit node
        if msgJson['from'] == msgData['reported']:
            return

        try:
            g.power_consensus_dict[msgData['reported']].append(json.loads(msgData['power']))
        except:
            g.power_consensus_dict[msgData['reported']] = [json.loads(msgData['power'])]
            g.power_thread[msgData['reported']] = tmo.Timeout("power_consensus", self.power_consensus,
                                                                      g.CONSENSUS_TIMEOUT, threadNum=msgData['reported'])
            g.power_thread[msgData['reported']].start()

        if len(g.power_consensus_dict[msgData['reported']]) >= len(g.node_list)-1:
            self.power_consensus(threadNum=msgData['reported'])

    def power_consensus(self, threadNum):
        """

        :param msgJson:
        :param threadNum:
        :return:
        """

        # if thread already popped, return
        if threadNum in g.power_thread:
            # kill and delete the timeout thread
            if g.power_thread[threadNum]:
                g.power_thread[threadNum].stop()
                g.power_thread.pop(threadNum)
                logging.warning(f"Power consensus timeout at node {g.my_port} with {len(g.power_consensus_dict[threadNum])}/{len(g.node_list)-1} votes")
            else:
                # if no timer running, assume it executed already somehow and return
                return

            aggArray = []

            g.power_consensus_dict[threadNum].append(json.loads(g.my_power))

            # attempt to estimate aggregator power reference
            for i in g.power_consensus_dict[threadNum]:
                for count, j in enumerate(i):
                    if count:
                        aggArray.append(j)
                    else:
                        aggArray.insert(0, j)

            logging.debug(f"Updating DMPC Z for node {g.my_port-8101} with average: {aggArray}, from {g.power_consensus_dict[threadNum]}")
            g.power_consensus_dict.pop(threadNum)

            # g.power_consensus_dict = {}
            # aggArray = [[g.NORMAL_POWER]]*3+[[0]]*(g.DMPC_HORIZON*3-3)

            logging.warning(f"Node {g.my_port} is estimating it's own power reference: {aggArray}")
            # update our power input
            updateDMPCPower(threadNum,power=json.dumps(aggArray))

            # set variables for recording senstivity and sending it to other nodes
            message_time = time.time()
            message_sensitivity = 1

            # hash of the from, to, sensitivity, and time fields and power signature to sign in the message
            sign_str = bf.get_hash(
                str(g.my_hash) + str(g.port_to_hash[threadNum]) + str(message_sensitivity) + str(message_time))
            # generate signature of the hash
            sign_bytes = crypt.gen_signature(sign_str.encode(g.ENCODING), g.my_pr_key)
            # convert signature to json-able format
            json_signature = base64.b64encode(bytearray(sign_bytes)).decode(g.ENCODING)

            try:
                # write sensitivity message
                message = {
                    "type": "sensitivity",
                    "from": g.my_hash,
                    "to": g.port_to_hash[threadNum],
                    "data": {
                        "sense": message_sensitivity,
                        "signature": json_signature
                    },
                    "time": message_time
                }

                # send the sensitivity back to the power sender
                sendMessage(message, threadNum)
            except Exception as e:
                print(f"Couldn't send power ref because {e}")
                logging.warning(
                    f"Unable to respond to power reference from port {self.port} to port {threadNum} because {e}")

    def respond_powerref(self, msgJson, msgData):
        """
        This function is responsible for responding to power reference messages

        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
        """
        # print(f"received power for {msgData['id']}")

        if g.DMPC_SIM and g.hash_to_port[msgJson['from']] not in g.power_count:
            g.power_count.append(g.hash_to_port[msgJson['from']])

        # stop the timer for the sending node
        if g.hash_to_port[msgJson['from']] in g.power_thread:
            g.power_thread[g.hash_to_port[msgJson['from']]].stop()
            g.power_thread.pop(g.hash_to_port[msgJson['from']])

        # if g.DMPC_SIM and msgJson['from'] in g.node_powers:
        #     msgPowerArray = np.array(json.loads(msgData['power']))
        #     prevPowerArray = np.array(g.node_powers[msgJson['from']])
        #     # check if power is making an unrealistic leap
        #     if max(abs(msgPowerArray-prevPowerArray/prevPowerArray))>0.4:
        #         logging.warning(f"Node {g.my_port} is requesting power because of Node {g.hash_to_port[msgJson['from']]}")
        #         self.request_power(msgJson)
        #         return

        # updateZDMPC(msgData["power"], g.hash_to_port[msgJson['from']])
        updateDMPCPower(g.hash_to_port[msgJson['from']],msgData["power"])

        # if g.my_port in g.TRAITOR_PORTS:
        #     return

        try:
            logging.debug(
                f"Message({g.hash_to_port[msgJson['from']]} - {self.port}): Received power ref from "
                f"{g.hash_to_port[msgJson['from']]} to {g.hash_to_port[msgJson['to']]}")
        except:
            do_nothing = True

        sign_str = bf.get_hash(str(msgJson['from']) + str(msgJson['to']) + str(msgData['power']) + str(msgJson['time']))
        signature = bytes(base64.b64decode(msgData['signature']))

        # if sending node is upstream of this node, send the sensitivity broadcast and record it
        if g.hash_to_port[msgJson['from']] in g.node_conn[str(self.port)]["upstream"] \
                and msgJson['to'] == g.my_hash \
                and crypt.check_signature(signature, sign_str.encode(g.ENCODING), g.hash_to_port[msgJson['from']]):
            # set variables for recording senstivity and sending it to other nodes
            message_time = time.time()
            message_sensitivity = 1

            # hash of the from, to, sensitivity, and time fields and power signature to sign in the message
            sign_str = bf.get_hash(str(g.my_hash) + str(msgJson['from']) + str(message_sensitivity) + str(message_time)
                                   + str(msgData['signature']))
            # generate signature of the hash
            sign_bytes = crypt.gen_signature(sign_str.encode(g.ENCODING), g.my_pr_key)
            # convert signature to json-able format
            json_signature = base64.b64encode(bytearray(sign_bytes)).decode(g.ENCODING)

            try:
                # write sensitivity message
                # this is where sensitivity would be calculated
                message = {
                    "type": "sensitivity",
                    "from": g.my_hash,
                    "to": msgJson['from'],
                    "data": {
                        "sense": message_sensitivity,
                        "powerdata": {
                            "from": msgJson['from'],
                            "to": msgJson['to'],
                            "time": msgJson['time'],
                            "power": msgData['power'],
                            "signature": msgData['signature']
                        },
                        "signature": json_signature
                    },
                    "time": message_time
                }
                logging.debug(
                    f"Message({self.port} - {g.hash_to_port[msgJson['from']]}): Sending sensitivity from {self.port} to {g.hash_to_port[msgJson['from']]}")

                # send the sensitivity back to the power sender
                sendMessage(message, g.hash_to_port[msgJson['from']])
            except Exception as e:
                print(f"Couldn't send power ref because {e}")
                logging.warning(
                    f"Unable to respond to power reference from port {self.port} to port {g.hash_to_port[msgJson['from']]} because {e}")
        else:
            logging.warning(
                f"Invalid power reference message received at port {self.port} from port {g.hash_to_port[msgJson['from']]}")

    def respond_sensitivity(self, msgJson, msgData):
        """
        This function is responsible for responding to sensitivity messages

        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
        """

        hasPower = 'powerdata' in msgData

        # print(f"received sense for {msgData['id']}")
        # stop timer for this thread
        threadNum = g.hash_to_port[msgJson['from']]
        if threadNum in g.sense_thread and g.sense_thread[threadNum]:
            g.sense_thread[threadNum].stop()
            g.sense_thread[threadNum] = None

        if g.DMPC_SIM and g.hash_to_port[msgJson['from']] not in g.sense_count:
            g.sense_count.append(g.hash_to_port[msgJson['from']])

        updateDMPCSense(g.hash_to_port[msgJson['from']])

        logging.debug(f"Message({g.hash_to_port[msgJson['from']]} - {self.port}): "
                      f"Received sensitivity from {g.hash_to_port[msgJson['from']]} to {g.hash_to_port[msgJson['from']]}")

        if hasPower:
            # generate the signed string from the message power data
            power_sign_str = bf.get_hash(str(msgData['powerdata']['from']) + str(msgData['powerdata']['to']) +
                                         str(msgData['powerdata']['power']) + str(msgData['powerdata']['time']))
            # load the power signature from the message power data
            power_signature = bytes(base64.b64decode(msgData['powerdata']['signature']))
            # generate the signed string from the message sensitivity data
            sense_sign_str = bf.get_hash(str(msgJson['from']) + str(msgJson['to']) +
                                     str(msgData['sense']) +str(msgJson['time']) + str(msgData['powerdata']['signature']))
        else:
            sense_sign_str = bf.get_hash(str(msgJson['from']) + str(msgJson['to']) +
                                         str(msgData['sense']) + str(msgJson['time']))
        # load the sensitivity signature from the message sensitivity data
        sense_signature = bytes(base64.b64decode(msgData['signature']))

        # check that sender is downstream from us,
        # and that the message is for us
        # and that this node signed the original power message
        # and that the sending node signed the sensitivity message
        if g.hash_to_port[msgJson['from']] in g.node_conn[str(self.port)]["downstream"] \
                and msgJson['to'] == g.my_hash \
                and (not hasPower or crypt.check_signature(power_signature, power_sign_str.encode(g.ENCODING), g.my_port)) \
                and crypt.check_signature(sense_signature, sense_sign_str.encode(g.ENCODING), g.hash_to_port[msgJson['from']]):

            # send same time value to all nodes
            message_time = time.time()

            # store power and sensitivity transactions
            # (consider them confirmed if we are the recipient of the sensitivity)
            if hasPower:
                g.this_nodes_transactions = bf.add_transaction(msgData['powerdata']['time'], "power",
                                                                msgData['powerdata']['from'], msgData['powerdata']['to'],msgData['powerdata']['power'])
            g.this_nodes_transactions = bf.add_transaction(msgJson['time'], "sense",
                                                           msgJson['from'], msgJson['to'],
                                                           msgData['sense'])
            # write to local storage
            ne.update_transactions()

            for j in g.node_list:  # broadcast confirmation to all seen nodes
                try:
                    # write confirmation message with record of power and sensitivity messages
                    message = {
                        "type": "confirm",
                        "from": g.my_hash,
                        "to": g.port_to_hash[j],
                        "data": {
                            "sensedata": {
                                "from": msgJson['from'],
                                "to": msgJson['to'],
                                "time": msgJson['time'],
                                "sense": msgData['sense'],
                                "signature": msgData['signature']
                            }
                        },
                        "time": message_time
                    }
                    if hasPower:
                        message['data']['powerdata'] = {
                                "from": msgData["powerdata"]['from'],
                                "to": msgData["powerdata"]['to'],
                                "time": msgData["powerdata"]['time'],
                                "power": msgData["powerdata"]['power'],
                                "signature": msgData["powerdata"]['signature']
                            }

                    logging.debug(f"Message({self.port} - {j}): "
                                  f"Sending Confirmation from {self.port} to {g.hash_to_port[msgJson['from']]}")
                    # broadcast that you're sending confirmation to i
                    sendMessage(message, j)
                except Exception as e:
                    logging.warning(
                        f"Unable to respond to sensitivity from port {self.port} to port {g.hash_to_port[msgJson['from']]} because {e}")


            # if transactions exceed block size and this node is a validator, propose a new block
            if (len(g.this_nodes_transactions) >= g.PROPOSE_TRIGGER
                or g.blockchain[-1].index == g.consensus_index+1) \
                    and g.my_hash in g.validator_list \
                    and g.last_proposed <= g.consensus_index:
                logging.debug(f"Proposing new block at port {g.my_port} from sensitivity")
                propose_block(msgJson, msgData)
        else:
            # case when there is an issue with the identities in the sensitivity message
            logging.warning(f"Invalid sensitivity message received at port {self.port} from port {g.hash_to_port[msgJson['from']]}")
            logging.warning(
                f"pcheck: {crypt.check_signature(power_signature, power_sign_str.encode(g.ENCODING), g.my_port)}, "
                f"scheck: {crypt.check_signature(sense_signature, sense_sign_str.encode(g.ENCODING), g.hash_to_port[msgJson['from']])}")

    def respond_confirm(self, msgJson, msgData):
        """
        This function will add the power/sensitivity transaction to the transaction list of this node
        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
        """
        # print(f"received confirm for {msgData['id']}")

        reportSense = "sensedata" not in msgData
        hasPower = 'powerdata' in msgData

        if hasPower and reportSense and msgData['powerdata']['to'] != g.my_hash:
            reportNode(msgData['powerdata']['to'])

        try:
            logging.debug(f"Message({g.hash_to_port[msgJson['from']]} - {self.port}): "
                          f"Received confirmation from {g.hash_to_port[msgJson['from']]} to {g.hash_to_port[msgJson['to']]}")
        except:
            do_nothing = True

        if hasPower:
            power_sign_str = bf.get_hash(str(msgData['powerdata']['from']) + str(msgData['powerdata']['to']) +
                                         str(msgData['powerdata']['power']) + str(msgData['powerdata']['time']))
            power_signature = bytes(base64.b64decode(msgData['powerdata']['signature']))

        if not reportSense:
            if hasPower:
                sense_sign_str = bf.get_hash(str(msgData['sensedata']['from']) + str(msgData['sensedata']['to']) +
                                             str(msgData['sensedata']['sense']) + str(msgData['sensedata']['time']) + str(msgData['powerdata']['signature']))
            else:
                sense_sign_str = bf.get_hash(str(msgData['sensedata']['from']) + str(msgData['sensedata']['to']) +
                                             str(msgData['sensedata']['sense']) + str(msgData['sensedata']['time']))
            sense_signature = bytes(base64.b64decode(msgData['sensedata']['signature']))

        # check signatures of both power
        # and sense messages
        # and that the sender of the confirm is the signer of the power message
        # verify that this node is the recipient of the broadcast
        if (not hasPower or crypt.check_signature(power_signature, power_sign_str.encode(g.ENCODING), g.hash_to_port[msgData['powerdata']['from']])) \
                and (reportSense or crypt.check_signature(sense_signature, sense_sign_str.encode(g.ENCODING), g.hash_to_port[msgData['sensedata']['from']])) \
                and (not hasPower or msgJson['from'] == msgData['powerdata']['from']) \
                and msgJson['to'] == g.my_hash:

            if hasPower:
                # store transactions
                g.this_nodes_transactions = bf.add_transaction(msgData['powerdata']['time'], "power",
                                                           msgData['powerdata']['from'], msgData['powerdata']['to'], msgData['powerdata']['power'])
            if not reportSense:
                g.this_nodes_transactions = bf.add_transaction(msgData['sensedata']['time'], "sense",
                                                           msgData['sensedata']['from'], msgData['sensedata']['to'],
                                                           msgData['sensedata']['sense'])
            # write to local storage
            ne.update_transactions()

            # if transactions exceed block size and this node is a validator, propose a new block
            if (len(g.this_nodes_transactions) >= g.PROPOSE_TRIGGER
                or g.blockchain[-1].index == g.consensus_index+1) \
                    and g.my_hash in g.validator_list\
                    and g.last_proposed <= g.consensus_index:
                logging.debug(f"Proposing new block at port {g.my_port} from confirm")
                propose_block(msgJson, msgData)
        else:
            logging.warning(
                f"Invalid confirm message received at port {self.port} from port {g.hash_to_port[msgJson['from']]}")
            logging.warning(
                f"pcheck: {crypt.check_signature(power_signature, power_sign_str.encode(g.ENCODING), g.hash_to_port[msgData['powerdata']['from']])}, "
                f"scheck: {reportSense or crypt.check_signature(sense_signature, sense_sign_str.encode(g.ENCODING), g.hash_to_port[msgData['sensedata']['from']])},"
                f"fromcheck:{msgJson['from'] == msgData['powerdata']['from']},"
                f"tocheck: {msgJson['to'] == g.my_hash}")

    def respond_addblock(self, msgJson, msgData):
        """
        This function will perform consensus on addblock messages received from other nodes
        then it will send the result to the smartcontract to finalize

        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
        """

        if msgData['newblock']['index'] > g.consensus_index:

            if msgJson['from'] not in g.consensus_id_list:
                g.consensus_id_list.append(msgJson['from'])
            else:
                logging.warning(f"node {g.my_port} received duplicate addblock from {g.hash_to_port[msgJson['from']]} with index {msgData['newblock']['index']}>{g.consensus_index}")
                return

            logging.debug(
                f"node {g.my_port} received addblock from {g.hash_to_port[msgJson['from']]} with index {msgData['newblock']['index']}>{g.consensus_index},"
                f"and votes: {len(g.consensus_id_list)}/{len(g.node_list)+1} "
                f"with hash: {msgData['newblock']['hash']}")

            loaded_transactions = bf.get_trans_objs(msgData['transactions'])

            # if hash has already been validated, just add it to the list
            if msgData['lasthash'] in g.consensus_array:
                g.consensus_array.append(msgData['lasthash'])
            # if not in the histogram yet, add them after validating the chain
            elif msgData['newblock']['previous_hash'] == g.blockchain[g.consensus_index].hash:
                g.consensus_array.append(msgData['lasthash'])
                # store the chain itself
                g.chain_dict[msgData['lasthash']] = [msgData['newblock']]

            for i in loaded_transactions:
                # histogram votes for specific transactions
                try:
                    g.trans_vote_dict[i.hash].append(msgJson['from'])
                except:
                    # add transaction to histogram if not in it
                    g.trans_vote_dict[i.hash] = [msgJson['from']]
                    g.trans_dict[i.hash] = i

            # start a timeout timer for addblock if not already started
            if not g.addblock_timer_thread:
                logging.debug(f"Addblock timer STARTED at node {g.my_port}")
                g.addblock_timer_thread = tmo.Timeout("addblock", bf.consensus_reset_and_send, g.CONSENSUS_TIMEOUT,None)
                g.addblock_timer_thread.start()

            # if consensus has timed out or received messages from all participating nodes
            if len(g.consensus_id_list) > len(g.node_list):

                # perform consensus
                bf.consensus_reset_and_send()

            # elif not g.consensus_time:
            #     # print("STARTING CONSENSUS TIMER")
            #     # Start recording time since consensus began
            #     g.consensus_time = time.time()
        else:
            logging.warning(f"Addblock index already agreed on at node {g.my_port} from node {g.hash_to_port[msgJson['from']]}"
                            f" cindex:{g.consensus_index} received:{msgData['newblock']['index']}")

    def respond_pay(self, msgJson, msgData):
        """
        This method will automatically insort payment transactions from the smartcontract

        :param msgJson: Json structure of message
        :param msgData: Json structure of message data
        """

        if g.BASE_PORT in g.port_to_hash and msgJson['from'] == g.port_to_hash[g.BASE_PORT]:

            g.this_nodes_transactions = bf.add_transaction(msgJson['time'], "payment", msgJson['from'], msgJson['to'],
                                                           msgData['value'])
            # update transactions in local storage
            ne.update_transactions()

            if g.consensus_index >= 0:
                # update the index as long as this is not a new node
                g.consensus_index = msgData['newblock']['index']

            # correct our blockchain if it doesnt match the agreed one
            # and we are not a new node
            if msgData['lasthash'] != g.blockchain[-1].hash and g.consensus_index >= 0:
                logging.debug(f"Node {g.my_port} is correcting its blockchain to idx:{msgData['newblock']['index']}, hash:{msgData['lasthash']}")
                g.blockchain[-1] = bf.get_block_objs([msgData['newblock']])[0]
                ne.update_chain()

                if msgData['T_hash'] != bf.get_transaction_list_hash():
                    loaded_transactions = bf.get_trans_objs(msgData['transactions'])
                    # correct our transactions
                    for i in g.this_nodes_transactions:
                        loaded_transactions = bf.add_transaction(i.timestamp, i.type, i.sender, i.recipient, i.value, listOfTransactions=loaded_transactions, port=g.my_port, my_chain=None)

                    logging.debug(f"Node {g.my_port} is correcting its transactions to size {len(loaded_transactions)}")
                    g.this_nodes_transactions = [x for x in loaded_transactions if x.timestamp > g.blockchain[-1].timestamp]
                    logging.debug(f"Node {g.my_port} transactions popped down to size: {len(g.this_nodes_transactions)}")

            # if transactions exceed block size and this node is a validator, propose a new block
            if (len(g.this_nodes_transactions) >= g.PROPOSE_TRIGGER
                or g.blockchain[-1].index == g.consensus_index+1) \
                    and g.my_hash in g.validator_list \
                    and g.last_proposed <= g.consensus_index:
                logging.debug(f"Proposing new block at port {g.my_port} from pay")
                propose_block(msgJson, msgData)

        else:
            logging.warning(f"Attempted payment observed at {g.my_port} from {g.hash_to_port[msgJson['from']]}")


def propose_block(msgJson, msgData):
    """
    This function will propose a block update to all of the other blocks
    """
    # if ready to add a new block, go ahead and put it on your blockchain
    if len(g.this_nodes_transactions) >= g.BLOCK_SIZE and g.blockchain[-1].index < g.consensus_index+1:
        bf.add_trans_to_block()

    # start latency recording of consensus process
    dr.write_msg_time(bf.get_hash(g.blockchain[-1].index, g.my_port), "consensus_process", g.consensus_index, g.my_port)

    # record request index to prevent duplication later
    g.last_proposed = g.blockchain[-1].index

    # create combination hash of transactions and blockchain
    loaded_block = g.blockchain[-1].to_dict()

    # reset consensus variables
    bf.reset_consensus(g.consensus_index)

    # Histogram the votes for the blockchain hash
    if loaded_block['previous_hash'] == g.blockchain[g.consensus_index].hash \
            and g.my_hash not in g.consensus_id_list:
        # store the chain itself
        if loaded_block['hash'] not in g.chain_dict:
            g.chain_dict[loaded_block['hash']] = [loaded_block]

        # go through all of the provided transactions to vote on them
        for i in g.this_nodes_transactions:
            # store votes for specific transactions
            try:
                g.trans_vote_dict[i.hash].append(g.my_hash)
            except:
                # add transaction to histogram if not in it
                g.trans_vote_dict[i.hash] = [g.my_hash]
                g.trans_dict[i.hash] = i

        # add blockchain
        g.consensus_array.append(g.blockchain[-1].hash)
        g.consensus_id_list.append(g.my_hash)
    else:
        logging.warning(f"Node {g.my_port} couldn't put its block in the addblock vote "
                        f"last block index: {g.blockchain[-1].index}, "
                        f"consensus index: {g.consensus_index}, "
                        f"last proposed: {g.consensus_index}, "
                        f"\nPrev:{loaded_block['previous_hash']}"
                        f"\nActual:{g.blockchain[g.consensus_index].hash}")

    for j in g.node_list:  # broadcast to all seen nodes
        try:
            logging.debug(f"Node {g.my_port} is requesting index:{g.blockchain[-1].index} from {j}")
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
                f"Unable to propose block from port {g.my_port} to port {g.hash_to_port[msgJson['from']]} because {e}")


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
                    if i and (g.BASE_PORT+i) not in g.node_list:
                        g.node_list.append(g.BASE_PORT+i)

                except Exception as e:
                    print(f"no connection detected at {g.BASE_PORT+i} because {e}")
                    do_nothing = True
        if not len(g.node_list):
            logging.debug("first node is securing its consensus index")
            g.consensus_index = g.blockchain[-1].index

        # send our own periodic power reference messages if not using dmpc simulation
        if g.DMPC_SIM:
            print("Awaiting LC-DMPC instructions")
        while not g.DMPC_SIM:
            # broadcast every MSG_PERIOD seconds
            time.sleep(g.MSG_PERIOD)
            # breakpoint()
            # print(f"sending powerrefs {time.time()}")

            # specify default power reference (using 1 for normalization)
            message_power = 1

            sendPowerref(message_power)


def sendPowerref(message_power):
    for i in g.node_conn[str(g.my_port)]["downstream"]:  # send power reference to downstream nodes

        # skip if node is offline
        if i not in g.node_list:
            continue

        # failsafe: dont send to yourself
        if (i != g.my_port and (i not in g.TARGET_NODES or random.random()>=g.NEGLECT_PROBABILITY)):
            # record time for the broadcast
            message_time = time.time()

            # hash of the from, to, power, and time fields to sign in the message
            sign_str = bf.get_hash(str(g.my_hash) + str(g.port_to_hash[i]) + str(message_power) + str(message_time))
            # generate signature of the hash
            sign_bytes = crypt.gen_signature(sign_str.encode(g.ENCODING), g.my_pr_key)
            # convert signature to json-able format
            json_signature = base64.b64encode(bytearray(sign_bytes)).decode(g.ENCODING)

            try:

                # create skeleton of message
                message = {
                    "type": "powerref",
                    "from": g.my_hash,
                    "to": g.port_to_hash[i],
                    "data": {
                        "power": message_power,
                        "signature": json_signature
                    },
                    "time": message_time
                }
                logging.debug(f"Message({g.my_port} - {i}): Sending power ref from {g.my_port} to {i}")

                # if i not in g.sense_thread or not g.sense_thread[i]:
                #     g.sense_thread[i] = tmo.Timeout("sense", report_sensitivity,
                #                                     g.CONSENSUS_TIMEOUT / 2, port=g.my_port, threadNum=i,arg=message)
                #     g.sense_thread[i].start()

                # send power reference to i
                sendMessage(message, i)

            except Exception as e:
                logging.warning(
                    f"Unable to send power reference broadcast from port {g.my_port} to port {i} because {e}")


def updateZDMPC(powerVal,fromport):
    """
    This function will tell the DMPC program to update the power reference input
    """
    if g.DMPC_SIM:
        # tell DMPC to update Z
        message = {
            "type": "updateZDMPC",
            "from_index": (fromport - 8101),
            "data": {"power": powerVal}
        }
        sendToDMPC(message)

def updateDMPCPower(fromport,power):
    """
    This function will tell the DMPC program to update the power reference input
    """
    if g.DMPC_SIM:
        # logging.error(f"Node {g.my_port} is telling dmpc to update V")
        # # only tell dmpc to update after all the messages have been received
        # if set(g.power_count) == set([x for x in g.node_conn[str(g.my_port)]['upstream'] if x in g.node_list]):
        g.power_count = []
        # tell DMPC to update V
        message = {
            "type": "powerDMPC",
            "to_index": (g.my_port-8101),
            "from_index": (fromport-8101),
            "data":{
                "power":power
            }
        }
        sendToDMPC(message)


def updateDMPCSense(fromport):
    """
    This function will tell the DMPC program to update the sensitivity input
    """
    if g.DMPC_SIM:
        # only tell dmpc to update after all the messages have been received
        if set(g.sense_count) == set([x for x in g.node_conn[str(g.my_port)]['upstream'] if x in g.node_list]):
            logging.debug(f"Updating dmpcsense from node {g.my_port}")
            g.sense_count = []
            # tell DMPC to update Psi
            message = {
                "type": "senseDMPC",
                "to_index": (g.my_port-8101),
                "from_index": (fromport-8101)
            }
            sendToDMPC(message)


def sendMessage(message, destPort, pr_key=None, myport=g.my_port):
    """
    This function sends a given message to a given port

    :param pr_key: private key (None defaults to global variable)
    :param message: The string message to send
    :param destPort: The port of the destination node
    :param myport: this node's port for debugging
    """
    # log message for tracking latency
    dr.write_msg_time(bf.get_hash(message['from'], message['to'], message['time']), message['type'], g.consensus_index, g.my_port)
    try:
        message = json.dumps(message)
    except json.JSONDecodeError:
        print(f"Message failed to send from port {myport} to port {destPort} because it couldn't be json formatted")
        logging.error(f"Message failed to send from port {myport} to port {destPort} because it couldn't be json formatted: {traceback.format_exc()}")

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
    s.shutdown(socket.SHUT_RDWR)
    s.close()


def sendToDMPC(message, myport=g.my_port):
    """
    This function sends a given message to the lcdmpc program

    :param message: The string message to send
    :param myport: this node's port for debugging
    """

    # failsafe
    if not g.DMPC_SIM:
        logging.error("Calling DMPC message sender when not testing DMPC!")
        return

    try:
        message = json.dumps(message)
    except json.JSONDecodeError:
        print(f"Message failed to send from port {myport} to DMPC because it couldn't be json formatted")
        logging.error(f"Message failed to send from port {myport} to DMPC because it couldn't be json formatted: {traceback.format_exc()}")

    # print(f"sending message to port{destPort}")

    # establish connection to port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((g.BASE_HOST, g.DMPC_PORT))

    # send all bytes of the message
    s.sendall(message.encode(g.ENCODING))

    # close connection
    s.shutdown(socket.SHUT_RDWR)
    s.close()


def report_sensitivity(msgJson,threadNum):
    msgData = msgJson['data']
    if threadNum and g.sense_thread[threadNum]:
        # stop the thread
        g.sense_thread[threadNum].stop()
        g.sense_thread[threadNum] = None

        if threadNum not in g.sense_count:
            g.sense_count.append(threadNum)

        updateDMPCSense(g.hash_to_port[msgJson['from']])

        # if executing from timeout, report the node that should have sent the sensitivity
        reportNode(msgJson['to'])

        # broadcast only the power reference

        # send same time value to all nodes
        message_time = time.time()

        # store power and sensitivity transactions
        # (consider them confirmed if we are the recipient of the sensitivity)
        g.this_nodes_transactions = bf.add_transaction(msgJson['time'], "power",
                                                       msgJson['from'], msgJson['to'],
                                                       msgData['power'])
        # write to local storage
        ne.update_transactions()

        for j in g.node_list:  # broadcast confirmation to all seen nodes
            try:
                # write confirmation message with record of power and sensitivity messages
                message = {
                    "type": "confirm",
                    "from": g.my_hash,
                    "to": g.port_to_hash[j],
                    "data": {
                        "powerdata": {
                            "from": msgJson['from'],
                            "to": msgJson['to'],
                            "time": msgJson['time'],
                            "power": msgData['power'],
                            "signature": msgData['signature']
                        }
                    },
                    "time": message_time
                }

                logging.debug(f"Message({g.my_port} - {j}): "
                              f"Sending Confirmation from {g.my_port} to {g.hash_to_port[msgJson['from']]}")
                # broadcast that you're sending confirmation to i
                sendMessage(message, j)
            except Exception as e:
                logging.warning(
                    f"Unable to respond to sensitivity from port {g.my_port} to port {g.hash_to_port[msgJson['from']]} because {e}")

        # if transactions exceed block size and this node is a validator, propose a new block
        if (len(g.this_nodes_transactions) >= g.PROPOSE_TRIGGER
            or g.blockchain[-1].index == g.consensus_index + 1) \
                and g.my_hash in g.validator_list \
                and g.last_proposed <= g.consensus_index:
            logging.debug(f"Proposing new block at port {g.my_port} from sensitivity")
            propose_block(msgJson, msgData)

        # return from the report phase


def reportNode(node):
    """
    This function will report a node to the smart contract for punishment
    :param node: hash of the node to report
    """
    logging.warning(f"Node {g.my_port} is reporting {g.hash_to_port[node]} to the smart contract")
    reportMsg = {
            "type": "report",
            "from": g.my_hash,
            "to": g.port_to_hash[g.BASE_PORT],
            "data": {
                "report": node
            },
            "time": time.time()
    }
    sendMessage(reportMsg, g.BASE_PORT)

