Storage Files
=============

NodeData
--------
Holds all of the files for each node, containing blockchains and transactions

Formatted: node<port-number>.json

balances.csv
------------
Record of UtilityToken balances throughout the block history for visualization

blockchain.log
--------------
Log of debugging, info, warning, and error messages from program execution

latencies.txt
-------------
Record of message send/receive times for calculating latency with the :ref:`latency_label` script

local_key.json
--------------
Json representative of local storage at each node, holding the public and private keys for each node

 .. note:: Normally, only the node who owns the private key would be able to view it, but they are grouped here for convenience

node_connections.json
---------------------
Json containing the upstream and downstream connections from node-to-node for the power/sensitivity exchange

public_keys.json
----------------
This json is representative of a key server, responsible for giving access to public keys to decrypt and verify digital signature

