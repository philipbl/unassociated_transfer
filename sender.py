import argparse
from itertools import zip_longest
import sys
import time

from scapy.all import *

import utils

SRC_MAC = "fe:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}"
DST_MAC = "33:33:{:02x}:{:02x}:{:02x}:{:02x}"


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


def send(data: str) -> None:
    data = data.encode('utf-8')

    # Encrypt the data
    encrypted_data = utils.encrypt_message(key=b'1234567894123456',
                                           message=data)

    # Integrity protect data
    hash_data = utils.hash_message(key=b'key', message=encrypted_data)

    assert len(encrypted_data) % 8 == 0

    for i, group in enumerate(grouper(encrypted_data + hash_data, 8)):
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
