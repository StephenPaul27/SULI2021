"""
This file will contain functions for encrypting and decrypting messages
"""

from all_imports import *


def decrypt(message):
    """
    This function will decrypt the provided bytes into a usable form

    :param message: message bytes to decrypt
    :return: decrypted message string
    """

    try:
        # load the incoming json
        inJson = json.loads(message.decode(g.ENCODING))
        fkey = bytes(base64.b64decode(inJson['key']))
        message = bytes(base64.b64decode(inJson['msg']))

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
    except:
        print(f"Message received at {g.my_port} was not formatted in a Json for decryption")
        logging.error(f"Message received at {g.my_port} was not formatted in a Json for decryption")
        return "ERROR"


def encrypt(message, destPort):
    """
    This function will encrypt a given string using hybrid encryption

    :param message: The string to encrypt
    :param destPort: The port of the destination node
    :return: encoded Json of the encrypted message and key
    """

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

    # put encrypted data into a json to send
    outJson = json.dumps({
        # data is encoded in base64 to work with Json
        "key": base64.b64encode(bytearray(fkey)).decode(g.ENCODING),
        "msg": base64.b64encode(bytearray(f.encrypt(message.encode(g.ENCODING)))).decode(g.ENCODING)
    })

    # return publicly encrypted fkey with symmetrically encrypted message
    return outJson.encode(g.ENCODING)
