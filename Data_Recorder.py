"""This file holds functions that will write data to storage for later analysis"""

import csv


def clear_balances():
    with open("Storage/balances.csv", 'r+') as f:
        f.truncate(0)


def write_balances(walletList,index):
    print("writing balances")
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
