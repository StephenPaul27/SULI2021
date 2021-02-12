from all_imports import *


def add_node():
    """
    This function will add a node to the local storage with a unique hash
    """

    # Read json from storage
    with open("Storage/nodes.json", "r") as f:
        node_file = json.load(f)

    # Create random hash for this new node
    sha = hasher.sha256()
    sha.update(str(time.time()).encode())

    # Create Json object for this new node
    node_file[str(len(node_file))] = {
        "port": BASE_PORT+len(node_file),
        "hash": sha.hexdigest()
    }

    # Write the updated json back to the file
    with open("Storage/nodes.json", "w") as f:
        json.dump(node_file, f, ensure_ascii=False, indent=4, sort_keys=True)

    # return the hash created
    return sha.hexdigest()


def del_node(id_number):
    """
    This function will delete a node from the local storage
    """
    # Read json from storage
    with open("Storage/nodes.json", "r") as f:
        node_file = json.load(f)

    # pop the specified node from the json
    node_file.pop(str(id_number), None)

    # Write the updated json back to the file
    with open("Storage/nodes.json", "w") as f:
        json.dump(node_file, f, ensure_ascii=False, indent=4, sort_keys=True)


def new_node(port):
    """
    This function will add a new node if it does not already exist in the file
    """
    # Read json from storage
    with open("Storage/nodes.json", "r") as f:
        node_file = json.load(f)

    # return if node already exists in file
    for i in range(0, len(node_file)):
        if node_file[str(i)]["port"] == port:
            return node_file[str(i)]["hash"]

    # else add a new node
    return add_node()