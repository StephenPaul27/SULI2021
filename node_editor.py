"""
This file contains functions that edit the local storage of the nodes
"""

from all_imports import *


def new_node(port):
    """
    This function will add a node to the local storage with a unique hash if it does not already exist

    :param port: port of the node to add
    :return: hash of the node added
    """

    # Read json from storage
    with open("Storage/nodes.json", "r") as f:
        node_file = json.load(f)

    # return if node already exists in file
    for i in list(node_file):
        if node_file[str(i)]["port"] == port:
            return node_file[str(i)]["hash"]

    # else

    # Create random hash for this new node
    sha = hasher.sha256()
    sha.update(str(time.time()).encode())

    # Create Json object for this new node
    node_file[str(port-g.BASE_PORT)] = {
        "port": port,
        "hash": sha.hexdigest(),
        "transactions": [],
        "chain": None
    }

    # Write the updated json back to the file
    with open("Storage/nodes.json", "w") as f:
        json.dump(node_file, f, ensure_ascii=False, indent=4, sort_keys=True)

    # return the hash created
    return sha.hexdigest()


def del_node(id_number):
    """
    This function will delete a node from the local storage

    :param id_number: ID of the node to update
    :return: None
    """
    # Read json from storage
    with open("Storage/nodes.json", "r") as f:
        node_file = json.load(f)

    # pop the specified node from the json
    node_file.pop(str(id_number), None)

    # Write the updated json back to the file
    with open("Storage/nodes.json", "w") as f:
        json.dump(node_file, f, ensure_ascii=False, indent=4, sort_keys=True)

def update_chain(port=g.my_port,chainList=None):
    """
    This function will write a blockchain into local storage

    :return: None
    """

    # assign the default value
    if chainList is None:
        chainList = g.blockchain

    # Read json from storage
    with open("Storage/nodes.json", "r") as f:
        node_file = json.load(f)

    # update the chain
    for i in list(node_file):
        if node_file[str(i)]["port"] == port:
            node_file[str(i)]["chain"] = bf.get_dict_list(chainList)

    # Write the updated json back to the file
    with open("Storage/nodes.json", "w") as f:
        json.dump(node_file, f, ensure_ascii=False, indent=4, sort_keys=True)

def get_transactions(port=g.my_port):
    """
    This function will return the transactions stored locally

    :return: transaction list
    """

    # Read json from storage
    with open("Storage/nodes.json", "r") as f:
        node_file = json.load(f)

    # read in the transactions from memory
    for i in list(node_file):
        if node_file[str(i)]["port"] == port:
            if node_file[str(i)]["transactions"]:
                return bf.get_trans_objs(node_file[str(i)]["transactions"])



    # return empty list if nothing found
    return []


def update_transactions(port=g.my_port, transactions=None):
    """
    This function will write the transactions into local storage

    :return: None
    """

    # update default value
    if transactions is None:
        transactions = g.this_nodes_transactions

    # Read json from storage
    with open("Storage/nodes.json", "r") as f:
        node_file = json.load(f)

    # update the chain
    for i in list(node_file):
        if node_file[str(i)]["port"] == port:
            node_file[str(i)]["transactions"] = bf.get_dict_list(transactions)

    # Write the updated json back to the file
    with open("Storage/nodes.json", "w") as f:
        json.dump(node_file, f, ensure_ascii=False, indent=4, sort_keys=True)