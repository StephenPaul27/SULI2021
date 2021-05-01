"""
This script will calculate the latencies stored by the main program and display them in a histogram
"""

import numpy as np
import matplotlib.pyplot as plt
import sys

def main():
    """
    This is the main function, it will create the histogram from the latency recording
    """
    msgDict = {}
    latencyArray = []
    with open("Storage/latencies.txt", "r") as f:
        filestring = f.readline()
        while filestring != "":
            filearray = filestring.split('|')   # split into TIME | TYPE | ID
            # siphon out the type
            if len(sys.argv) <= 1 or "all" in sys.argv or filearray[1] in sys.argv:
                if filearray[2] in msgDict:
                    latencyArray.append(float(filearray[0]) - msgDict[filearray[2]])
                    if latencyArray[-1] > 6:
                        print(f"Message: {filearray[1]}|{filearray[2]}|{filearray[3]}|{filearray[4]}|")
                else:
                    msgDict[filearray[2]] = float(filearray[0])
            filestring = f.readline()
    a = np.array(latencyArray)
    plt.hist(a, bins=40)
    plt.xticks(fontsize=24, rotation=0)
    plt.yticks(fontsize=24)
    plt.title(f"1-Node Communication Traffic\n({len(latencyArray)} Messages, 20-nodes, 100 Blocksize)",fontsize=30,weight="bold")
    plt.xlabel("Durations (s)", fontsize=24)
    plt.ylabel("# of occurrences", fontsize=24)
    plt.show()


if __name__ == '__main__':
    """
    This executes the main function upon script execution
    """
    main()