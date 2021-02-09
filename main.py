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
    blockchain.append(bf.create_genesis_block())
    #breakpoint()
    print(f"Genesis block: {blockchain[0].hash}")
    # my_host = "localhost"
    #my_host = input("which is my host? ")
    my_port = int(sys.argv[1])
    port_to_hash[my_port] = my_hash
    # print(node_list)
    #my_port = int(input("which is my port? "))
    receiver = comm.Receiver(BASE_HOST, my_port)
    # my_friends_host = input("what is your friend's host? ")
    # my_friends_port = int(input("what is your friend's port?"))
    sender = comm.Sender(BASE_HOST, my_port)
    threads = [receiver.start(), sender.start()]
"""
This executes the main function upon script execution
"""
if __name__ == '__main__':
    main()