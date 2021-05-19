Pseudocode
==========

.. note:: "Necessary Parameters" refers to parameters relevant to the pseudocode

.. _pseudo_consensus_response:

Consensus Response:
-------------------

    ::

        Necessary Parameters:
            message from node contributing to consensus

        Assert that the node is in validator list
        Assert that the node has not already voted on consensus
        Assert that the node is proposing consensus for the correct block index

        Put node in list of voted validators
        If a vote has already been created for this blockhash
            Add voter node’s hash to the list created for the blockhash (to “submit” its vote)
        If this node’s vote introduces a new block and its “previous_hash” field matches the last block on the blockchain
            Create a vote for this blockhash

        Assert that there are no duplicate transactions in the attached list
            For each transaction in the attached transaction list:
                Try to submit a vote from this node for the transaction hash
                If that fails:
                    Create a vote for this transaction hash and store the transaction
                    Then submit a vote from this node for the transaction hash

        Begin timeout thread for the Consensus_Process (in case some nodes don’t respond in a timely manner)

        If all validators have now voted begin the Consensus_Process


.. _pseudo_decrypt:

Decrypt:
--------

    ::

        Necessary Parameters:
            JSON package to decrypt

        Extract signature, encrypted key, and encrypted message from JSON
        Decrypt symmetric key with this node’s private key
        Decrypt message with decrypted symmetric key
        Retrieve public key of sender node using its “from” hash of the decrypted message
        Calculate hash of decrypted message
        Verify signature using retrieved public key and hash of decrypted message

        Return: Decrypted and decoded message

.. _pseudo_encrypt:

Encrypt:
--------

    ::

        Necessary Parameters:
            message to encrypt
            destination node

        Generate symmetric encryption key
        Create hash of message
        Retrieve public key using destination node
        Create signature using this node’s private key and message hash
        Encrypt message using symmetric key
        Encrypt symmetric key using public key
        Output_JSON = {
                            signature,
                            encrypted symmetric key,
                            encrypted message
                      }

        Return: Encoded Output_JSON

.. _pseudo_power_consensus_process:

Power Consensus Process (Aggregator Fabrication):
-------------------------------------------------

    ::

        This process enacts upon timing out while awaiting a power reference message

        At the node that detected the disconnect:

            Kill/erase the timer thread that called this function
            The thread identifier is actually the port of the disconnected node, so report it to the smart contract
            Send power request to all other connected nodes

        At the nodes receiving the power request:

            Upon receipt of power request, nodes reply with their current power/last received power reference

        At the node that detected the disconnect:

            Upon receipt of power reply from each node:
                start a timer for consensus if not started already
                add received power to list of node powers

            if received power from all nodes or the timeout above executes:
                kill the thread (if applicable)
                create an empty aggregated power reference

                for each recorded power in list of node powers:
                    (Unofficial Estimation:)
                    insert current power at beginning of aggregated reference
                    insert horizon at end of aggregated reference

                Tell DMPC program to update the power reference input (V) with the fabricated aggregated reference

                Attempt to respond with sensitvity as normal


.. _pseudo_timeouts:

Timeouts:
---------

    ::

        Necessary Parameters:
            Callback function for when the timer expires
            Duration of the timer
            (Optional) Thread identifier for timer threads in a list
            (Optional) Argument for the Callback function

        Record instantiation time of this thread
        Begin infinite thread loop:
            if time since instantiation exceeds specified duration:
                enact the callback function (with argument if applicable)
                exit/kill this thread
            delay a small amount of time (0.05 seconds)



.. _pseudo_update_wallets:

Update Wallets:
---------------

    ::

        Necessary Parameters:
            None

        Clear current wallet/balances dictionary

        For each block in the blockchain:
            For each transaction in the block:
                Add transaction value to recipient balance

        For each transaction in current transaction list:
            Add transaction value to recipient balance


.. _pseudo_validator_consensus:

Validator Consensus:
--------------------

    ::

        Necessary Parameters:
            None (accepts a thread identifier from timeout though)

        Kill the timer thread
        Sort validators’ votes by quantity

        Append most popular voted block to our blockchain
        Insort any transaction (by timestamp) that has a majority vote
        Pop any transactions that date before this new block

        Pay validators incentive if their vote matches the majority
        Pay validators penalty if their vote does not match
        Pay any reported nodes a penalty if they have been reported by a majority of nodes

        Select new validators
        Update wallets
        Update chain in file
        Update transactions in file
        Reset consensus variables

