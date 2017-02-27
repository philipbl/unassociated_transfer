from __future__ import generators, division, print_function, with_statement
import argparse
from collections import namedtuple
import json
import logging
import struct

import pyshark
from zfec import Decoder

import utils

logging.basicConfig(level=logging.DEBUG)
LOGGER = logging.getLogger(__name__)

FILTER = "wlan[4] == 0x33 and wlan[5] == 0x33 and wlan[16] == 0xfe"

Packet = namedtuple('Packet',
                    ['home_id', 'send_flag', 'possible_loss',
                     'total_packets', 'sequence', 'data'])


def get_global_sequence():
    with open(utils.CONFIG_FILE_NAME) as f:
        config = json.load(f)
        return config.get('global_sequence', 0)


def set_global_sequence(seq):
    with open(utils.CONFIG_FILE_NAME, 'r') as f:
        config = json.load(f)

    config['global_sequence'] = seq

    with open(utils.CONFIG_FILE_NAME, 'w') as f:
        json.dump(config, f)


def process_packet(packet):
    src = packet.wlan.sa
    dst = packet.wlan.da

    # hh:hh:hh:xx:xx:xx
    header, src_data = src.split(':')[:2], src.split(':')[2:]
    # 33:33:xx:xx:xx:xx
    dst_data = dst.split(':')[2:]

    data = ''.join(src_data + dst_data)
    data = bytearray.fromhex(data)

    header = int(header, base=16)

    # iiii ii10 fnnt tttt tsss ssss
    home_id = (header >> 18)
    send_flag = (header >> 15) & 0b1
    possible_loss_index = (header >> 13) & 0b11
    total = ((header >> 7) << 1) & 0b1111111
    sequence = header & 0b1111111

    possible_loss = utils.FEC_LOSS[possible_loss_index]

    return Packet(home_id, send_flag, possible_loss, total, sequence, data)


def get_packet(interface):
    capture = pyshark.LiveCapture(interface=interface,
                                  monitor_mode=True,
                                  capture_filter=FILTER)
    packets = {}
    num_packets = -1

    for p in capture.sniff_continuously():
        packet = process_packet(p)

        LOGGER.debug("Sequence: %s", packet.sequence)
        LOGGER.debug("Total: %s", packet.total)

        yield (sequence, total, data)


def get_packets(interface):
    total_packets = None
    packets = []

    for packet in get_packet(interface):
        sequence, total, data = packet

        if total_packets is None or total_packets != total:
            total_packets = total
            decoder = Decoder(total_packets // 2, total_packets)
            packets = []  # Restart collecting

        packets.append((data, sequence))

        if len(packets) >= total_packets // 2:
            # UnFEC packets
            data = decoder.decode(*zip(*packets))
            yield data
            packets = []


def get_data(interface, encryption_key, integrity_key):
    for packets in get_packets(interface):

        # Get all of the data from the packets
        iv_data = packets[0] + packets[1]
        global_sequence_data = packets[2]
        encrypted_data = bytearray()
        for value in packets[3:-2]:
            encrypted_data.extend(value)
        mac_data = packets[-2] + packets[-1]

        LOGGER.debug("IV: %s", list(iv_data))
        LOGGER.debug("Global sequence number: %s", list(global_sequence_data))
        LOGGER.debug("Encrypted data: %s", list(encrypted_data))
        LOGGER.debug("MAC: %s", list(mac_data))

        # Check the integrity of the message
        if mac_data != utils.hash_message(key=integrity_key,
                                          message=global_sequence_data + encrypted_data):
            LOGGER.warning("MAC is different -- the data is invalid. Retrying...")
            continue

        # Make sure this is a new packet and not a replayed old one
        global_sequence, = struct.unpack(utils.GLOBAL_SEQUENCE_FORMAT,
                                         global_sequence_data)
        old_global_sequence = get_global_sequence()
        if global_sequence <= old_global_sequence:
            LOGGER.error("Received old global sequence number (%s <= %s)",
                         global_sequence,
                         old_global_sequence)
            continue

        # Update global sequence number
        set_global_sequence(global_sequence)

        # Decrypt data
        data = utils.decrypt_message(key=encryption_key,
                                     iv=bytes(iv_data),
                                     message=bytes(encrypted_data))
        return data


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('interface')
    args = parser.parse_args()

    with open(utils.CONFIG_FILE_NAME) as f:
        config = json.load(f)

    data = get_data(args.interface,
                    config['encryption_key'].encode(),
                    config['integrity_key'].encode())
    print(data)
