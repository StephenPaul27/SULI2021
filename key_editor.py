from all_imports import *

def create_key(port):
    """
    This function will create a private and public key pair for a node if it does not already exist
    Then it will write the keys to a file
    The public_keys file represents a publicly accessible server/database of public keys, whereas the local_keys
    file represents local storage accessible only to each node

    :param port: port number associated with the node
    :return: private key (generated or read)
    """

    # Read json from storage
    with open("Storage/local_key.json", "r") as f:
        pri_key_file = json.load(f)

    # check if key already exists (must be in the private key storage)
    if str(port) in pri_key_file:

        # decode from base64 byte string
        key_decode = base64.b64decode(pri_key_file[str(port)]["private"])

        key_decode = serialization.load_pem_private_key(
            bytes(key_decode),
            password=None,
            backend=default_backend()
        )

        print("found private key: ", key_decode)

        # return private key object
        return key_decode
    else:

        # otherwise prepare to generate and store new keys
        with open("Storage/public_keys.json", "r") as f:
            pub_key_file = json.load(f)

        # generate the private and public keys for this node
        pr_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,      # reduce key size for faster runtime
                backend=default_backend()
            )
        pu_key = pr_key.public_key()
        # serialize the keys to write to files
        pr_write = base64.b64encode(
            bytearray(
                pr_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                    )
                )
            ).decode(ENCODING)
        pu_write = base64.b64encode(
            bytearray(
                pu_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                )
            ).decode(ENCODING)

        # write both keys into the local key storage (this would normally be local to each node)
        pri_key_file[str(port)] = {
            "private": str(pr_write),
            "public": str(pu_write)
        }
        # write the public key to a publicly available area
        pub_key_file[str(port)] = str(pu_write)

        # Write the updated jsons back to their files
        with open("Storage/public_keys.json", "w") as f:
            json.dump(pub_key_file, f, ensure_ascii=False, indent=4, sort_keys=True)
        with open("Storage/local_key.json", "w") as f:
            json.dump(pri_key_file, f, ensure_ascii=False, indent=4, sort_keys=True)

        # return the created private key
        return pr_key


def get_pub_key(port):
    """
    This function will read the public key of a port
    """

    # Read json from storage
    with open("Storage/public_keys.json", "r") as f:
        pub_key_file = json.load(f)

    if str(port) in pub_key_file:
        # decode key from base64 string
        key_decode = base64.b64decode(pub_key_file[str(port)])

        # return a public key object
        return serialization.load_pem_public_key(
                bytes(key_decode),
                backend=default_backend()
            )
    else:
        return None
