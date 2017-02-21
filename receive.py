from __future__ import generators, division, print_function, with_statement
import argparse
import json
import logging
import struct

import pyshark
import utils

logging.basicConfig(level=logging.DEBUG)
LOGGER = logging.getLogger(__name__)

FILTER = "wlan[4] == 0x33 and wlan[5] == 0x33 and wlan[16] == 0xfe"


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

    header, src_data = src.split(':', 2)[1:]
    dst_data = dst.split(':')[2:]

    data = ''.join(src_data.split(':') + dst_data)
    data = bytearray.fromhex(data)

    header = int(header, base=16)
    last_packet = 0x01 & header
    sequence = header >> 1

    return sequence, last_packet, data


def get_packets(interface):
    capture = pyshark.LiveCapture(interface=interface,
                                  monitor_mode=True,
                                  capture_filter=FILTER)
    packets = {}
    num_packets = -1

    for packet in capture.sniff_continuously():
        sequence, last_packet, data = process_packet(packet)

        LOGGER.debug("Sequence: %s", sequence)
        LOGGER.debug("Last packet: %s", last_packet)

        if last_packet:
            num_packets = sequence + 1

        if sequence not in packets:
            LOGGER.debug("Received %s", sequence)
            packets[sequence] = data

        LOGGER.debug("")

        if len(packets) == num_packets:
            yield packets

            # Start over
            packets = {}
            num_packets = -1


def get_data(interface, encryption_key, integrity_key):
    for packets in get_packets(interface):
        packets = sorted(packets.items())

        # Get all of the data from the packets

        iv_data = packets[0][1] + packets[1][1]
        global_sequence_data = packets[2][1]
        encrypted_data = bytearray()
        for key, value in packets[3:-2]:
            encrypted_data.extend(value)
        mac_data = packets[-2][1] + packets[-1][1]

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
