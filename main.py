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

"""
This is the main function, it executes the rest of the code
"""
def main():

    global my_hash

    # format the log
    logging.basicConfig(filename='Storage/blockchain.log', filemode='a',
                        format='%(asctime)s %(levelname)s: %(message)s',
                        level=logging.DEBUG)

    # Identify start of new log
    if my_port == BASE_PORT:
        logging.info("New Session Started")

    # create random hash to represent this node (if needed)
    my_hash = ne.new_node(my_port)

    # create genesis block for this node
    blockchain.append(bf.create_genesis_block())

    logging.info(f"Node started at port {my_port} with hash {my_hash}")
    print(f"Node started at port {my_port}")

    # add port and hash into the map
    port_to_hash[my_port] = my_hash
    hash_to_port[my_hash] = my_port

    # set up server and client objects
    receiver = comm.Receiver(BASE_HOST, my_port)
    sender = comm.Sender(BASE_HOST, my_port)

    threads = [receiver.start(), sender.start()]


"""
This executes the main function upon script execution
"""
if __name__ == '__main__':
    main()