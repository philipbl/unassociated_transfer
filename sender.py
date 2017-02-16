import argparse
from itertools import zip_longest
import sys
import time

from scapy.all import *

SRC_MAC = "fe:{:02x}:{}:{}:{}:{}"
DST_MAC = "33:33:{}:{}:{}:{}"


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


def send(data):
    # Convert data to bytes
    data_bytes = ["{:02x}".format(ord(c)) for c in data]

    print(data_bytes)
    for i, group in enumerate(grouper(data_bytes, 8, "00")):
        src = SRC_MAC.format(i, *group[:4])
        dst = DST_MAC.format(*group[4:])

        packet = Ether(src=src, dst=dst)
        packet.show()
        sendp(packet)
        time.sleep(.5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send to unassociated WiFi client')
    parser.add_argument('data', nargs='?', default=sys.stdin)

    args = parser.parse_args()

    if isinstance(args.data, str):
        data = args.data
    else:
        data = args.data.read()

    send(data)
