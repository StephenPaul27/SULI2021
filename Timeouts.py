"""
This file will contain functions for timing out consensus and other messages
"""

from all_imports import *

def time_check():
    """
    This function will check if any timers have expired
    """

    Now = time.time()

    # check for introduction response timeout
    if g.response_timer and Now-g.response_timer > g.CONSENSUS_TIMEOUT:
        logging.warning(f"Node {g.my_port} is performing response consensus from timeout")
        bf.consensus()
        bf.reset_consensus(g.blockchain[-1].index)
        # reset the timer
        g.response_timer = 0
    if g.addblock_timer and Now-g.addblock_timer > g.CONSENSUS_TIMEOUT:
        logging.warning(f"Node {g.my_port} is performing addblock consensus from timeout")
        bf.consensus()
        bf.reset_consensus(g.blockchain[-1].index)
        # reset the timer
        g.addblock_timer = 0