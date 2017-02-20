import argparse
from itertools import zip_longest
import json
import logging
import struct
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


def send(data: bytes, encryption_key: bytes, integrity_key: bytes) -> None:
    if len(data) % 16 != 0:
        LOGGER.error("Length of data must be a multiple of 16. It is currently %s.",
                     len(data))
        return

    iv_data = utils.generate_iv()
    global_sequence_data = struct.pack(utils.GLOBAL_SEQUENCE_FORMAT,
                                       int(time.time()))
    encrypted_data = utils.encrypt_message(key=encryption_key,
                                           iv=iv_data,
                                           message=data)
    mac_data = utils.hash_message(key=integrity_key,
                                  message=global_sequence_data + encrypted_data)

    LOGGER.debug("IV: %s", iv_data)
    LOGGER.debug("Global sequence number: %s", global_sequence_data)
    LOGGER.debug("Encrypted data: %s", encrypted_data)
    LOGGER.debug("MAC: %s", mac_data)

    all_data = iv_data + global_sequence_data + encrypted_data + mac_data

    if len(all_data) % 8 != 0:
        LOGGER.error("All data is not divisible by 8!")
        return

    total_packets = len(all_data) / 8

    if total_packets >= 128:  # 7 bits long
        LOGGER.error("The data is too big and too many packets need to be sent.")
        return

    retries = 5
    for retry in range(retries):
        for sequence, group in enumerate(grouper(all_data, 8)):
            header = (sequence << 1) + (0 if sequence != total_packets - 1 else 1)

            src = SRC_MAC.format(header, *group[:4])
            dst = DST_MAC.format(*group[4:])

            LOGGER.debug("Sending packet: Ether(src=%s, dst=%s)", src, dst)
            sendp(Ether(src=src, dst=dst))

            time.sleep(.2)

        time.sleep(5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send to unassociated WiFi client')
    parser.add_argument('data', nargs='?', default=sys.stdin)

    args = parser.parse_args()

    with open(utils.CONFIG_FILE_NAME) as f:
        config = json.load(f)

    if isinstance(args.data, str):
        data = args.data
    else:
        data = args.data.read()

    send(data.encode(),
         config['encryption_key'].encode(),
         config['integrity_key'].encode())
