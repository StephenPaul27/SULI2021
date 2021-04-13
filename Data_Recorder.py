"""This file holds functions that will write data to storage for later analysis"""

import csv
import time


def clear_latencies():
    """
    This function will clear the latency log
    """
    with open("Storage/latencies.txt", 'r+') as f:
        f.truncate(0)


def write_msg_time(id,type,index):
    """
    This function will write a log of a message's send/receive time to calculate latency
    :param id: id of the sending message to be matched with its reception
    :param type: type of message if there are different latency patterns
    """
    with open("Storage/latencies.txt", "a") as f:
        f.write(str(time.time())+'|'+str(type)+'|'+str(id)+'|'+str(index)+'\n')


def clear_balances():
    """
    This function will clear the csv that balances are written to
    """
    with open("Storage/balances.csv", 'r+') as f:
        f.truncate(0)


def write_balances(walletList,index):
    """
    This function will write the current balances to a csv file to be displayed as a graph
    :param walletList: list of wallet values for each node
    :param index: block index to keep
    """

    balance_dict = {'index':[]}
    size_tracker = 0

    with open("Storage/balances.csv", 'r') as f:
        r = csv.DictReader(f)
        # creates a dictionary of csv file
        for row in r:
            for key in row.keys():
                try:
                    balance_dict[key].append(int(row[key]))
                except:
                    balance_dict[key] = [int(row[key])]
                # keep track of length of record
                if len(balance_dict[key])>size_tracker:
                    size_tracker+=1

    balance_dict['index'].append(index)

    # add the new values into the dict
    for key in walletList.keys():
        try:
            # if node is already present in the history
            balance_dict[key].append(walletList[key])
        except:
            if size_tracker:
                # if new node introduced, add a history of zeroes to their key
                balance_dict[key] = (size_tracker-1) * [0]
            else:
                balance_dict[key] = []
            # then add the new value
            balance_dict[key].append(walletList[key])

    with open("Storage/balances.csv", 'w') as f:
        writer = csv.writer(f)
        writer.writerow(balance_dict.keys())
        writer.writerows(zip(*balance_dict.values()))
