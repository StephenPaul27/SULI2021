"""
This file will contain functions for timing out any process
"""

from all_imports import *


class Timeout(threading.Thread):
    """
    This class will act as a general thread timer for any process
        :ref:`(Pseudocode) <pseudo_timeouts>`
    """

    def __init__(self, timer_type, functionCall, duration=g.CONSENSUS_TIMEOUT, port=g.my_port, threadNum=None, arg=None):
        """
        This function initializes the class object with the type, start time, and thread running condition
        :param timer_type: type of timer for debugging purposes
        :param functionCall: callback function for after timeout expires
        :param duration: duration of the timer
        :param port: port of node calling this function for debugging
        :param threadNum: thread number to pass along if this thread is part of a list of threads
        :param arg: argument to pass into the callback function
        """
        threading.Thread.__init__(self, name=f"{timer_type}_timer")
        self.type = timer_type
        self.duration = duration
        self.time = time.time()     # record the start time
        self.running = True
        self.port = port
        self.threadNum = threadNum
        self.functionCall = functionCall
        self.arg = arg

    def stop(self):
        """
        This function will effectively stop the thread by setting the run condition to false
        """
        self.running = False

    def run(self):
        """
        This is the bulk of the thread, it will repeatedly check if the time has exceeded the duration
        """
        try:
            # loop until stopped or broken
            while self.running:
                # if time exceeds duration
                if time.time()-self.time > self.duration:
                    # perform the consensus
                    logging.warning(f"Node {self.port} is performing {self.type} consensus from timeout "
                                    f"(threadNum:{self.threadNum})")
                    if self.arg:
                        self.functionCall(self.arg, threadNum=self.threadNum)
                    else:
                        self.functionCall(threadNum=self.threadNum)

                    break
                # sleep a little to reduce frequency of checks
                time.sleep(0.05)
        except Exception as e:
            logging.error(f"Node {self.port} Timer of type: {self.type} exited because {traceback.format_exc()}")
