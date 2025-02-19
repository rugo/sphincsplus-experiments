"""
Takes a file with parameter choices and only outputs the interesting ones.
Sorts by runtime, then only outputs signatures that are smaller than previous.
"""

import sys

fname = sys.argv[1]

data = open(fname).read()

rows = data.split("\n")

data = []

for row in rows:
    row_l = row.split("\t")
    if len(row_l) < 9:
        continue
    data.append(list(map(int, row_l)))


# sorted by number of hash colls
sorted_data = sorted(data, key=lambda x: x[1])

min_size = 2<<32

for row in sorted_data:
    # pin winternitz parameter to 16
    if (row[8] == 16 or row[8] == 256) and row[0] < min_size:
        print(*row)
        min_size = row[0]
