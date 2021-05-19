Storage Files
=============

balances.csv
------------
Record of UtilityToken balances throughout the block history for visualization

blockchain.log
--------------
Log of debugging, info, warning, and error messages from program execution

contractStorage.json
--------------------
Json for storing the last block index and current validators

FileSizes.csv
-------------
CSV containing file size progression as transactions are recorded (There is a bug where file sizes are recorded for earlier-than-current transactions)

latencies.txt
-------------
Record of message send/receive times for calculating latency with the :ref:`latency_label` script

local_key.json
--------------
Json representative of local storage at each node, holding the public and private keys for each node

 .. note:: Normally, only the node who owns the private key would be able to view it, but they are grouped here for convenience

node_connections_dmpc.json
--------------------------
Json containing the upstream and downstream connections from node-to-node for the power/sensitivity exchange according to the default setup of LC-DMPC.

node_connections_fork.json
--------------------------
Json containing node connections in a forking configuration.

node_connections_linear.json
----------------------------
Json containing node connections in linear configuration.

NodeData
--------
Folder holding all of the files for each node, containing blockchains and transactions

Formatted: node<port-number>.json

public_keys.json
----------------
This json is representative of a key server, responsible for giving access to public keys to decrypt and verify digital signature

TimeoutData.txt
---------------

Saved version of latencies.txt containing recordings of timeout events affecting the consensus processes.
