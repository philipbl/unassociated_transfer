import argparse
from itertools import zip_longest
import logging
import sys
import time

from scapy.all import *

import utils

logging.basicConfig(level=logging.DEBUG)
LOGGER = logging.getLogger(__name__)

SRC_MAC = "fe:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}"
DST_MAC = "33:33:{:02x}:{:02x}:{:02x}:{:02x}"


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


def send(data: str) -> None:
    data = data.encode('utf-8')

    encrypted_data = utils.encrypt_message(key=b'1234567894123456',
                                           message=data)
    mac_data = utils.hash_message(key=b'key', message=encrypted_data)

    LOGGER.debug("Encrypted data: %s", encrypted_data)
    LOGGER.debug("MAC: %s", mac_data)

    all_data = encrypted_data + mac_data

    assert len(all_data) % 8 == 0
    total_packets = len(all_data) / 8

    if total_packets > 127:
        LOGGER.error("The data is too big and too many packets need to be sent.")
        return

    retries = 5
    for retry in range(retries):
        for i, group in enumerate(grouper(all_data, 8)):
            sequence = i << 1 + 0 if i != total_packets - 1 else 1

            src = SRC_MAC.format(sequence, *group[:4])
            dst = DST_MAC.format(*group[4:])

            LOGGER.debug("Sending packet: Ether(src=%s, dst=%s)", src, dst)
            sendp(Ether(src=src, dst=dst))

            time.sleep(.2)

        time.sleep(5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send to unassociated WiFi client')
    parser.add_argument('data', nargs='?', default=sys.stdin)

    args = parser.parse_args()

    if isinstance(args.data, str):
        data = args.data
    else:
        data = args.data.read()

    send(data)
