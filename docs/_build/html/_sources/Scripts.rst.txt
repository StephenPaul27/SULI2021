Supplementary Scripts
=====================

.. _latency_label:

Latency.py
----------

    .. automodule:: Latency
        :members:

node_runner
-----------

This bash script is used to run multiple instances of the blockchain program.
The simulation duration, node quantity, and starting ports can be set.
If a negative duration is provided, the simulation will run until the user stops it with "pkill -f main.py".
This scripts usage is: "bash node_runner <# nodes> <starting port> <duration>
