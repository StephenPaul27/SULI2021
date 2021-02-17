This is a repo for my code during the SULI 2021 Internship

The code can run a single node from main.py
terminal usage: python main.py <port number>
<port number> - port number to start the node. 
 
I have been using a base port number of 8080 and nodes are run on different ports locally, so a user could run multiple nodes by running "python main.py 8080" then in another terminal "python main.py 8081"

To run a large number of nodes, I created the bash script "node_runner" that can be used to run an arbitrary number of nodes in the background for an arbitrary duration
terminal usage: bash node_runner <number of nodes> <base port> <test duration (seconds)>
<number of nodes> - number of nodes to run
<base port> - port to start making connections from (i.e. 8080, then it would loop until 8080 + <number of nodes>)
<test duration> - number of seconds before node processes are killed
