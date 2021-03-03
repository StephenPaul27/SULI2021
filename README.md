This is a repo for my code during the SULI 2021 Internship

The code can run a single node from main.py
<br>terminal usage: <b>python main.py \<port-number\></b>
<br><u><i>port-number</u></i> - port number to start the node. 
 
I have been using a base port number of 8080 and nodes are run on different ports locally, so a user could run multiple nodes by running "python main.py 8080" then in another terminal "python main.py 8081"

To run a large number of nodes, I created the bash script "node_runner" that can be used to run an arbitrary number of nodes in the background for an arbitrary duration
<br>terminal usage: <b>bash node_runner \<number-of-nodes\> \<base-port\> \<test-duration\></b>
<br><u><i>number-of-nodes</u></i> - number of nodes to run
<br><u><i>base-port</u></i> - port to start making connections from (i.e. 8080, then it would loop until 8080 + number-of-nodes)
<br><u><i>test-duration</u></i> - number of seconds before node processes are killed

Several of the storage files are kept as 
such for convenience.  In reality public keys 
would be provided by some sort of keyserver, 
while node data, blockchains, and private keys 
would all be stored local to each node.