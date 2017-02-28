from __future__ import generators, division, print_function, with_statement
import argparse
from collections import namedtuple
from itertools import dropwhile
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
                    ['home_id', 'send_flag', 'packets_needed',
                     'total', 'sequence', 'data'])


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


def process_packets(packets):
    for packet in packets:
        src = packet.wlan.sa
        dst = packet.wlan.da

        # hh:hh:hh:xx:xx:xx
        header, src_data = src.split(':')[:3], src.split(':')[3:]
        # 33:33:xx:xx:xx:xx
        dst_data = dst.split(':')[2:]

        data = ''.join(src_data + dst_data)
        data = bytearray.fromhex(data)

        header = int(''.join(header), base=16)

        # iiii ii10 fnnt tttt tsss ssss
        home_id = (header >> 18)
        send_flag = (header >> 15) & 0b1
        possible_loss_index = (header >> 13) & 0b11
        total = ((header >> 7) << 1) & 0b1111111
        sequence = header & 0b1111111

        possible_loss = utils.FEC_LOSS[possible_loss_index]
        packets_needed = possible_loss * total

        if not packets_needed.is_integer():
            LOGGER.error("packets_needed must be an integer: %s", packets_needed)
        packets_needed = int(packets_needed)

        yield Packet(home_id=home_id,
                     send_flag=send_flag,
                     total=total,
                     packets_needed=packets_needed,
                     sequence=sequence,
                     data=data)


def get_packets(interface, home_id):
    capture = pyshark.LiveCapture(interface=interface,
                                  monitor_mode=True,
                                  capture_filter=FILTER)
    captured_packets = process_packets(capture.sniff_continuously())
    packet = next(captured_packets)
    LOGGER.debug("Received packet: %s", packet)
    packets = [packet]

    for packet in captured_packets:

        # Make sure this is a packet we want to receive
        if packet.home_id != home_id:
            LOGGER.warning("Received packet with unknown home ID: %s",
                           packet.home_id)
            continue

        # Make sure these packets are coming from the right series of packets
        if packet.send_flag != packets[-1].send_flag:
            # Clear out all of the previously collected packets
            LOGGER.debug("Different send_flag, clearing old data")
            packets = [packet]
            continue

        LOGGER.debug("Received packet: %s", packet)
        packets.append(packet)

        if len(packets) == packet.packets_needed:
            LOGGER.debug("Received enough packets")
            yield packets


def get_message(interface, home_id):
    for packets in get_packets(interface, home_id):
        m = packets[0].total
        k = packets[0].packets_needed
        packets = [(packet.data, packet.sequence) for packet in packets]

        try:
            decoder = Decoder(k, m)
            LOGGER.debug("Encoding data: k=%s, m=%s", k, m)
            data = decoder.decode(*zip(*packets))
            data = map(bytearray, data)
        except Exception:
            LOGGER.exception("Unable to decode packets")
            continue

        # Remove padding
        last_packet = list(reversed(list(dropwhile(lambda x: x == 0, reversed(data[-1])))))
        data[-1] = bytearray(last_packet)

        # Combine data
        all_data = bytearray()
        for d in data:
            all_data.extend(d)

        yield all_data


def receive(interface, encryption_key, integrity_key, home_id=0x3F):
    for message in get_message(interface, home_id):

        # Get all of the data from the packets
        iv_data = message[:16]
        global_sequence_data = message[16:24]
        encrypted_data = message[24:-32]
        mac_data = message[-32:]

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

    data = receive(args.interface,
                   config['encryption_key'].encode(),
                   config['integrity_key'].encode())
    print(data)
