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
    with open(f"Storage/NodeData/node{port}.json", "r") as f:
        node_file, successful = tryLoad(f, port)

    if not successful:
        logging.warning(f"unable to read node file for port: {port} FINAL")
        return

    # return if node already exists in file
    if "hash" in node_file:
        return node_file["hash"]

    # else

    # Create random hash for this new node
    sha = hasher.sha256()
    sha.update(str(time.time()).encode())

    # Create Json object for this new node
    node_file = {
        "port": port,
        "hash": sha.hexdigest(),
        "transactions": [],
        "chain": []
    }
    # Write the updated json back to the file
    with open(f"Storage/NodeData/node{port}.json", "w") as f:
        json.dump(node_file, f, ensure_ascii=False, indent=4)

    # now add node connection if needed (not to consensus server though)
    if port is not g.BASE_PORT:
        # Read json from storage
        with open(f"Storage/{g.node_connection_file}.json", "r") as f:
            node_file, successful = tryLoad(f, port)

        if not successful:
            logging.warning(f"unable to read node connections for port: {port} FINAL")
            return

        if str(port) not in node_file:
            if port not in node_file[list(node_file)[-1]]['downstream']:
                node_file[list(node_file)[-1]]['downstream'].append(port)

            node_file[str(port)] = {
                "downstream": [],
                "upstream": [int(list(node_file)[-1])]
            }
            g.node_conn = node_file
            # Write the updated json back to the file
            with open(f"Storage/node_connections.json", "w") as f:
                json.dump(node_file, f, ensure_ascii=False, indent=4)


    # return the hash created
    return sha.hexdigest()


def update_chain(port=g.my_port,chainList=None):
    """
    This function will write a blockchain into local storage
    :param port: port of this node
    :param chainList: blockchain to write
    """

    # assign the default value
    if chainList is None:
        chainList = g.blockchain

    # Read json from storage
    with open(f"Storage/NodeData/node{port}.json", "r") as f:
        node_file, successful = tryLoad(f, port)

    if not successful:
        logging.warning(f"unable to read chain for port: {port} FINAL")
        return

    # update the chain
    node_file["chain"] = bf.get_dict_list(chainList)

    # Write the updated json back to the file
    with open(f"Storage/NodeData/node{port}.json", "w") as f:
        json.dump(node_file, f, ensure_ascii=False, indent=4)


def get_transactions(port=g.my_port):
    """
    This function will return the transactions stored locally
    :param port: port of this node
    :return: transaction list
    """

    # Read json from storage
    with open(f"Storage/NodeData/node{port}.json", "r") as f:
        node_file, successful = tryLoad(f, port)

    if not successful:
        logging.warning(f"unable to read transactions for port: {port} FINAL")
        return []

    # read in the transactions from memory
    return bf.get_trans_objs(node_file["transactions"])


def update_transactions(port=g.my_port, transactions=None):
    """
    This function will write the transactions into local storage
    :param port: port of this node
    :param transactions: transactions to write
    """

    # update default value
    if transactions is None:
        transactions = g.this_nodes_transactions

    # Read json from storage
    with open(f"Storage/NodeData/node{port}.json", "r") as f:
        node_file, successful = tryLoad(f, port)

    if not successful:
        logging.warning(f"unable to read transactions for port: {port} FINAL")
        return

    # update the chain
    node_file["transactions"] = bf.get_dict_list(transactions)

    # Write the updated json back to the file
    with open(f"Storage/NodeData/node{port}.json", "w") as f:
        json.dump(node_file, f, ensure_ascii=False, indent=4)

    if g.first_node:
        dr.record_filesize(g.blockchain[-1].index, len(transactions), g.BLOCK_SIZE)


def tryLoad(f, port):
    """
    This function will attempt to load a json file 5 times with a small delay to allow for a read-write collision to
    clear
    :param f: file to read
    :param port: port of this node
    :return: (loaded json file, boolean of success)
    """
    successful = False
    node_file = None
    for i in range(5):
        try:
            # try to read the file
            node_file = json.load(f)
            successful = True
            break
        except json.decoder.JSONDecodeError:
            # if there are problems, wait and try again 5 times
            logging.warning(f"unable to read {f} for port: {port}, trying again")
            time.sleep(0.05)

    return node_file, successful