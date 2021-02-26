"""
This file will contain functions for encrypting and decrypting messages
"""

from all_imports import *


def decrypt(package):
    """
    This function will decrypt the provided bytes into a usable form

    :param message: message bytes to decrypt
    :return: decrypted message string
    """

    try:
        # load the incoming json
        # print("decrypting message: ", package)
        inJson = json.loads(package.decode(g.ENCODING))
        signature = bytes(base64.b64decode(inJson['sign']))
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

        # decrypt the message
        message = f.decrypt(message).decode(g.ENCODING)

        # Get the pub key from the port given
        try:
            # print("decoded message: ",message)
            msgJson = json.loads(message)
            if(msgJson['type']=='intro' or msgJson['type'] == 'response'):
                msgData = json.loads(msgJson['data'])
                pub_key = ke.get_pub_key(msgData['fromport'])
            else:
                pub_key = ke.get_pub_key(g.hash_to_port[msgJson['from']])
        except Exception as e:
            logging.warning(f"Decrypted message at port {g.my_port} was not formatted as a json for the signature: {e}")

        # verify signature using the decrypted message's 'from' field
        try:
            pub_key.verify(
                signature,
                message.encode(g.ENCODING),
                padding.PSS(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except:
            print("Signature failed")
            logging.warning(f"Message at port {g.my_port} did not match its signature")
            return None

        return message
    except Exception as e:
        print(f"Message received at {g.my_port} was not formatted in a Json for decryption: {e}")
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

    # sign un-encrypted message bytes
    signature = g.my_pr_key.sign(
        message.encode(g.ENCODING),
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

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
        "sign": base64.b64encode(bytearray(signature)).decode(g.ENCODING),
        "key": base64.b64encode(bytearray(fkey)).decode(g.ENCODING),
        "msg": base64.b64encode(bytearray(f.encrypt(message.encode(g.ENCODING)))).decode(g.ENCODING)
    })

    # print("encryption json: ", {outJson})

    # return publicly encrypted fkey with symmetrically encrypted message
    return outJson.encode(g.ENCODING)
