"""
Blockchain Network Code
Stephen Paul

format: python <filename>.py <port>

This program will create a node to be used in a blockchain-like network.
Nodes will communicate with each other via P2P where each node is both server and client.
The goal is to attain stability when <=1/3rd of nodes provide faulty information
"""

#imports
from all_imports import *


def main():
    """
    This is the main function, it executes the rest of the code
    """

    # format the log
    logging.basicConfig(filename='Storage/blockchain.log', filemode='a',
                        format='%(asctime)s %(levelname)s: %(message)s',
                        level=logging.DEBUG)

    # Identify start of new log
    if g.my_port == g.BASE_PORT:
        logging.info("New Session Started")

    # create random hash to represent this node (if needed)
    g.my_hash = ne.new_node(g.my_port)

    # create encryption keys for this node (if needed)
    g.my_pr_key = ke.create_key(g.my_port)
    # print(f"my_pr_key at initialization = {g.my_pr_key}")

    # create genesis block for this node
    g.blockchain.append(bf.create_genesis_block())
    print("This node's Genesis block hash: ", g.blockchain[0].hash)

    # Log node startup
    logging.info(f"Node started at port {g.my_port} with hash {g.my_hash}")
    print(f"Node started at port {g.my_port}")

    # add port and hash into the map
    g.port_to_hash[g.my_port] = g.my_hash
    g.hash_to_port[g.my_hash] = g.my_port

    # set up server and client objects
    receiver = comm.Receiver(g.BASE_HOST, g.my_port)
    sender = comm.Sender(g.BASE_HOST, g.my_port)

    threads = [receiver.start(), sender.start()]


if __name__ == '__main__':
    """
    This executes the main function upon script execution
    """
    main()