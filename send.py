from __future__ import generators, division, print_function, with_statement
import argparse
import json
import logging
import math
import struct
import sys
import time

try:
    from itertools import zip_longest
except ImportError:
    from itertools import izip_longest
    zip_longest = izip_longest

from scapy.all import *
from zfec.easyfec import Encoder

import utils

logging.basicConfig(level=logging.DEBUG)
LOGGER = logging.getLogger(__name__)

SRC_MAC = "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}"
DST_MAC = "33:33:{:02x}:{:02x}:{:02x}:{:02x}"


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


def send(data, encryption_key, integrity_key, send_flag=0, home_id=0x3f, possible_loss=.5):
    if len(data) % 16 != 0:
        LOGGER.error("Length of data must be a multiple of 16. It is currently %s.",
                     len(data))
        return

    if int(send_flag) >= 2: # 1 bit long
        LOGGER.error("Send flag is too large: %s. It must be less than 2.",
                     send_flag)
        return

    if possible_loss not in utils.FEC_LOSS:
        LOGGER.error("'possible_loss' must be one of these values: %s", utils.fec_loss)
        return

    if len(utils.FEC_LOSS) > 4:
        LOGGER.error("FEC_LOSS list is too large: %s. It must be only 4 elements.",
                     len(utils.FEC_LOSS))
        return

    if home_id >= 64:  # 6 bits long
        LOGGER.error("home_id is too large: %s. It must be less than 64.",
                     home_id)
        return

    iv_data = utils.generate_iv()
    global_sequence_data = struct.pack(utils.GLOBAL_SEQUENCE_FORMAT,
                                       int(time.time()))
    encrypted_data = utils.encrypt_message(key=encryption_key,
                                           iv=iv_data,
                                           message=data)
    mac_data = utils.hash_message(key=integrity_key,
                                  message=global_sequence_data + encrypted_data)

    # Convert from str to list of ints (bytearrays)
    iv_data = bytearray(iv_data)
    global_sequence_data = bytearray(global_sequence_data)
    encrypted_data = bytearray(encrypted_data)
    mac_data = bytearray(mac_data)

    LOGGER.debug("IV: %s", list(iv_data))
    LOGGER.debug("Global sequence number: %s", list(global_sequence_data))
    LOGGER.debug("Encrypted data: %s", list(encrypted_data))
    LOGGER.debug("MAC: %s", list(mac_data))

    all_data = iv_data + global_sequence_data + encrypted_data + mac_data

    # Add padding
    if len(all_data) % utils.TOTAL_DATA != 0:
        padding = utils.TOTAL_DATA - (len(all_data) % utils.TOTAL_DATA)
        all_data.extend(['\x00'] * padding)

    # Add FEC
    k = len(all_data) // utils.TOTAL_DATA
    m = int(math.ceil(round(k * (1 / (1 - possible_loss))) / 2) * 2)
    encoder = Encoder(k, m)
    encoded_data = encoder.encode(all_data)
    LOGGER.debug("Encoding data: k=%s, m=%s", k, m)

    all_encoded_data = bytearray()
    for x in encoded_data:
        all_encoded_data.extend(x)

    if len(all_data) % utils.TOTAL_DATA != 0:
        LOGGER.error("Total data must be divisible by %s. It's size is %s",
                     utils.TOTAL_DATA, len(all_data))
        return

    total_packets = len(all_encoded_data) // utils.TOTAL_DATA
    LOGGER.debug("Total packets: %s", total_packets)

    if total_packets % 2 != 0:
        LOGGER.error("Total number of packets must be even")
        return

    if total_packets >= 128:  # 7 bits long
        LOGGER.error("The data is too big and too many packets need to be sent.")
        return

    # iiii ii10 fnnt tttt t000 0000
    header = (home_id << 18) + \
             (0b10 << 16) + \
             (int(send_flag) << 15) + \
             (utils.FEC_LOSS.index(possible_loss) << 13) + \
             ((total_packets >> 1) << 7)

    for sequence, group in enumerate(grouper(all_encoded_data, utils.TOTAL_DATA)):
        # iiii ii10 fnnt tttt tsss ssss
        packet_header = header + sequence

        src = SRC_MAC.format((packet_header & 0xFF0000) >> 16,
                             (packet_header & 0x00FF00) >> 8,
                             (packet_header & 0x0000FF),
                             *group[:3])
        dst = DST_MAC.format(*group[3:])

        LOGGER.debug("Sending packet: Ether(src=%s, dst=%s)", src, dst)
        sendp(Ether(src=src, dst=dst))

        time.sleep(.2)


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
