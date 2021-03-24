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

    # open new file if needed for the node data
    with open(f"Storage/NodeData/node{g.my_port}.json", "w+") as f:
        # if file is not formatted as json, format it as an empty json
        try:
            json.load(f)
        except json.JSONDecodeError:
            json.dump({}, f, ensure_ascii=False, indent=4)
        else:
            if g.REWRITE_FILES:
                json.dump({}, f, ensure_ascii=False, indent=4)


    logging.basicConfig(filename='Storage/blockchain.log', filemode='a',
                            format='%(asctime)s %(module)s:%(lineno)d - %(levelname)s: %(message)s',
                            level=logging.DEBUG)

    # start consensus smart contract server if not started
    try:
        # see if server is up already (will throw exception if connection refused)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((g.BASE_HOST, g.BASE_PORT))
        s.close()
    except ConnectionRefusedError as e:
        g.first_node = True
        # format the log
        if g.REWRITE_FILES and g.first_node:
            print("truncating log")
            with open("Storage/blockchain.log","r+") as f:
                f.truncate(0)

        # Identify start of new log
        logging.info("New Session Started")
        # start consensus server
        consensus = cons.Server(g.BASE_HOST, g.BASE_PORT)
        consensus.start()




    # create random hash to represent this node (if needed)
    g.my_hash = ne.new_node(g.my_port)

    # create encryption keys for this node (if needed)
    g.my_pr_key = ke.create_key(g.my_port)
    # print(f"my_pr_key at initialization = {g.my_pr_key}")

    # create genesis block for this node
    g.blockchain = bf.restore_chain()
    ne.update_chain()

    # read transactions from local storage
    g.this_nodes_transactions = ne.get_transactions()

    print("This node's Genesis block hash: ", g.blockchain[0].hash)
    print("This node's ID hash:", g.my_hash)

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