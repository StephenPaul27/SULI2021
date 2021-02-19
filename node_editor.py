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
    for i in range(0, len(node_file)):
        if node_file[str(i)]["port"] == port:
            return node_file[str(i)]["hash"]

    # else

    # Create random hash for this new node
    sha = hasher.sha256()
    sha.update(str(time.time()).encode())

    # Create Json object for this new node
    node_file[str(g.my_port-g.BASE_PORT)] = {
        "port": g.my_port,
        "hash": sha.hexdigest(),
        "transactions": None,
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

# def read_chain():
#     """
#     This function will read a blockchain from local storage
#
#     :param port: port of the node to read
#     :return: chain read
#     """
#
#     # Read json from storage
#     with open("Storage/nodes.json", "r") as f:
#         node_file = json.load(f)
#
#     # return if node exists in file
#     for i in list(node_file):
#         if node_file[str(i)]["port"] == g.my_port:
#             return node_file[str(i)]["chain"]
#
#     return None

def update_chain():
    """
    This function will write a blockchain into local storage

    :param port: Port of the node to write the chain for
    :param chain: The chain to write to the node
    :return: None
    """

    # using local import here because of circular structure
    import blockchain_funcs as bf

    # Read json from storage
    with open("Storage/nodes.json", "r") as f:
        node_file = json.load(f)

    # update the chain
    for i in range(0, len(node_file)):
        if node_file[str(i)]["port"] == g.my_port:
            node_file[str(i)]["chain"] = bf.get_blocks()

    # Write the updated json back to the file
    with open("Storage/nodes.json", "w") as f:
        json.dump(node_file, f, ensure_ascii=False, indent=4, sort_keys=True)