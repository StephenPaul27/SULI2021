"""
This file will contain functions for encrypting and decrypting messages
"""

from all_imports import *


def decrypt(package, port=g.my_port, pr_key=None):
    """
    This function will decrypt the provided bytes into a usable form

    :param pr_key: private key to decrypt with
    :param port: port for debugging
    :param package: message bytes to decrypt
    :return: decrypted message string
    """

    # correct the default private key
    if pr_key is None:
        pr_key = g.my_pr_key

    try:
        # load the incoming json
        # print("decrypting message: ", package)
        inJson = json.loads(package.decode(g.ENCODING))
    except json.JSONDecodeError as e:
        print(f"Message received at {port} was not formatted in a Json for decryption: {e}")
        logging.error(f"Message received at {port} was not formatted in a Json for decryption")
        return "ERROR"

    signature = bytes(base64.b64decode(inJson['sign']))
    fkey = bytes(base64.b64decode(inJson['key']))
    message = bytes(base64.b64decode(inJson['msg']))

    # use this node's private key to decrypt the symmetric key
    if pr_key:
        fkey = pr_key.decrypt(
            fkey,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    else:
        logging.warning(f"Node at port {port} doesn't have a private key to decrypt with")

    # get the symmetric key object
    f = Fernet(fkey)

    # decrypt the message
    message = f.decrypt(message).decode(g.ENCODING)

    # Get the pub key from the port given
    try:
        # print("decrypted message: ",message)
        msgJson = json.loads(message)
        if msgJson['type'] == 'intro' or msgJson['type'] == 'response':
            msgData = msgJson['data']
            pub_key = ke.get_pub_key(msgData['fromport'])
        else:
            pub_key = ke.get_pub_key(g.hash_to_port[msgJson['from']])
    except Exception as e:
        logging.warning(f"Decrypted message at port {port} was not formatted as a json for the signature: {e}")
        return "ERROR"

    # verify signature using the decrypted message's 'from' field
    try:
        pub_key.verify(
            signature,
            fkey,
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        print(f"Signature failed at {port} from port {g.hash_to_port[msgJson['from']]} because \"{e}\"")
        logging.warning(f"Message at port {port} did not match its signature: {e}")
        return None

    return message


def encrypt(message, destPort, pr_key=None):
    """
    This function will encrypt a given string using hybrid encryption

    :param pr_key: private key of the node trying to encrypt
    :param message: The string to encrypt
    :param destPort: The port of the destination node
    :return: encoded Json of the encrypted message and key
    """

    # correct the default key
    if pr_key is None:
        pr_key = g.my_pr_key

    # generate a random symmetric key
    fkey = Fernet.generate_key()

    # create symmetric encryptor
    f = Fernet(fkey)

    # obtain public key for the destination port
    pubkey = ke.get_pub_key(destPort)

    # sign un-encrypted symmetric key (instead of message to avoid data size issue)
    signature = pr_key.sign(
        fkey,
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # print("message signed successfully")

    # ensure that a public key is available
    if pubkey:
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
        "sign": base64.b64encode(bytearray(signature)).decode(g.ENCODING),
        "key": base64.b64encode(bytearray(fkey)).decode(g.ENCODING),
        "msg": base64.b64encode(bytearray(f.encrypt(message.encode(g.ENCODING)))).decode(g.ENCODING)
    })

    # print("encryption json: ", {outJson})

    # return publicly encrypted fkey with symmetrically encrypted message
    return outJson.encode(g.ENCODING)
