This is a repo for my code during the SULI 2021 Internship

The code can run a single node from main.py
<br>terminal usage: <b>python main.py \<port-number\></b>
<br><u><i>port-number</u></i> - port number to start the node. 
 
I have been using a base port number of 8100 which will always host the smart contract server.  Nodes are run on different ports locally, so a user could run multiple nodes by running "python main.py 8101" then in another terminal "python main.py 8102"

To run a large number of nodes, I created the bash script "node_runner" that can be used to run an arbitrary number of nodes in the background for an arbitrary duration
<br>terminal usage: <b>bash node_runner \<number-of-nodes\> \<base-port\> \<test-duration\></b>
<br><u><i>number-of-nodes</u></i> - number of nodes to run
<br><u><i>base-port</u></i> - port to start making connections from (i.e. 8100, then it would loop until 8100 + number-of-nodes)
<br><u><i>test-duration</u></i> - number of seconds before node processes are killed

Blockchains and transactions for nodes are stored in their own local files in Storage/NodeData

Errors and general debugging information is written to blockchain.log by the logging module

Some global variables can be altered to change the testing environment, i.e. g.REWRITE_FILES will erase the log and node files prior to execution