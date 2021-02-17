"""
This file will contain functions for encrypting and decrypting messages
"""

from all_imports import *

def decrypt(message):
    if b'gAAAAA' in message:
        msg_array = message.split(b'gAAAAA')
        if len(msg_array) != 2:
            logging.warning(f"message received at port {g.my_port} doesn't have 2 sections")

        msg_array[1] = b'gAAAAA' + msg_array[1]
        fkey = msg_array[0]
        message = msg_array[1]

        # use this node's private key to decrypt the symmetric key
        if g.my_pr_key:
            fkey = g.my_pr_key.decrypt(
                fkey,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode(g.ENCODING)
        else:
            logging.warning(f"Node at port {g.my_port} doesn't have a private key to decrypt with")

        # use the symmetric key to decrypt and return the message
        f = Fernet(fkey)
        return f.decrypt(message).decode(g.ENCODING)
    else:
        print("Message missing '|'")
        logging.warning(f"Message recevied at {g.my_port} missing '|'")

def encrypt(message, destPort):

    # generate a random symmetric key
    fkey = Fernet.generate_key()

    # create symmetric encryptor
    f = Fernet(fkey)

    # obtain public key for the destination port
    pubkey = ke.get_pub_key(destPort)

    # ensure that a public key is available
    if (pubkey):
        # encrypt the symmetric key using the public key
        fkey = pubkey.encrypt(
            fkey,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    else:
        # log error if public key is missing
        print("No public key detected at port " + str(destPort))
        logging.error("No public key detected at port " + str(destPort))

    # print(f"final message during encryption: {fkey + b'|' + f.encrypt(message.encode(g.ENCODING))}")

    # return publicly encrypted fkey with symmetrically encrypted message
    return fkey + f.encrypt(message.encode(g.ENCODING))
