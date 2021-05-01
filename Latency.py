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
                    if int(filearray[3]) == 8 and int(filearray[4])==8105:
                        latencyArray.append(float(filearray[0]) - msgDict[filearray[2]])
                else:
                    msgDict[filearray[2]] = float(filearray[0])
            filestring = f.readline()
    print(f"Data: {latencyArray}")
    a = np.array(latencyArray)
    plt.hist(a, bins=40)
    plt.xticks(fontsize=24, rotation=270)
    plt.yticks(fontsize=24)
    plt.title(f"1-Node Communication\nLatencies\n({len(latencyArray)} Events, Blocksize:60)",fontsize=30,weight="bold")
    plt.xlabel("Latency (s)",fontsize=24)
    plt.ylabel("# of occurrences",fontsize=24)
    plt.show()


if __name__ == '__main__':
    """
    This executes the main function upon script execution
    """
    main()