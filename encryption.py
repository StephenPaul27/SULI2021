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
    :returns: decrypted message string
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

    if g.DMPC_SIM and "type" in inJson:
        return package.decode(g.ENCODING)

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
        # log reception of message for tracking latency
        dr.write_msg_time(bf.get_hash(msgJson['from'], msgJson['to'], msgJson['time']), msgJson['type'], g.consensus_index)
        if msgJson['type'] == 'intro' or msgJson['type'] == 'response':
            msgData = msgJson['data']
            pub_port = msgData['fromport']
        else:
            pub_port = g.hash_to_port[msgJson['from']]
    except Exception as e:
        logging.warning(f"Decrypted message at port {port} was not formatted as a json for the signature: {e}")
        return "ERROR"

    # verify signature using the decrypted message's 'from' field
    if not check_signature(signature, bf.get_hash(message).encode(g.ENCODING), pub_port):
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
    :returns: encoded Json of the encrypted message and key
    """

    # correct the default key
    if pr_key is None:
        pr_key = g.my_pr_key

    # generate a random symmetric key
    fkey = Fernet.generate_key()

    msg_hash = bf.get_hash(message).encode(g.ENCODING)

    # create symmetric encryptor
    f = Fernet(fkey)

    # obtain public key for the destination port
    pubkey = ke.get_pub_key(destPort)

    # sign un-encrypted symmetric key (instead of message to avoid data size issue)
    signature = gen_signature(msg_hash, pr_key);
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


def gen_signature(message, pr_key):
    """
    This function will generate a signature for a given message
    :param message: message to be signed
    :param pr_key: sending node's private key
    :returns: signature
    """

    return pr_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def check_signature(signature, message, pub_port):
    """
    This function will check whether the signature of a message maches a given public key
    :param signature: provided signature
    :param message: message claimed to be signed with signature
    :param pub_key: public key of sender
    :returns: boolean value representing validity
    """
    # get the public key of the port
    pub_key = ke.get_pub_key(pub_port)
    # verify the signature with the message
    try:
        pub_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False