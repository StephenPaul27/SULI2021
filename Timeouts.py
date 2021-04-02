"""
This file will contain functions for timing out consensus and other messages
"""

from all_imports import *


class Timeout(threading.Thread):
    """
    This class will act as a thread timer for timing out messages/consensus
    """

    def __init__(self, timer_type, functionCall, duration=g.CONSENSUS_TIMEOUT, port=g.my_port):
        """
        This function initializes the class object with the type, start time, and thread running condition
        :param timer_type: type of timer for debugging purposes
        :param functionCall: function to call after timeout expires
        :param duration: duration of the timer
        :param port: port of node calling this function for debugging
        """
        threading.Thread.__init__(self, name=f"{timer_type}_timer")
        self.type = timer_type
        self.duration = duration
        self.time = time.time()     # record the start time
        self.running = True
        self.port = port
        self.functionCall = functionCall

    def stop(self):
        """
        This function will effectively stop the thread by setting the run condition to false
        """
        self.running = False

    def run(self):
        """
        This is the bulk of the thread, it will check if the time has exceeded the duration
        """
        try:
            # loop until stopped or broken
            while self.running:
                # if time exceeds duration
                if time.time()-self.time > self.duration:
                    # perform the consensus
                    logging.warning(f"Node {self.port} is performing {self.type} consensus from timeout")
                    self.functionCall()
                    break
                # sleep a little to reduce frequency of checks
                time.sleep(0.1)
        except Exception as e:
            logging.debug(f"Node {self.port} Timer of type: {self.type} exited because {e}")
