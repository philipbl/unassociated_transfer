import argparse
import json
import logging

import pyshark
import utils

logging.basicConfig(level=logging.DEBUG)
LOGGER = logging.getLogger(__name__)

FILTER = "wlan[4] == 0x33 and wlan[5] == 0x33 and wlan[16] == 0xfe"


def process_packet(packet):
    src = packet.wlan.sa
    dst = packet.wlan.da

    header, *src_data = src.split(':')[1:]
    dst_data = dst.split(':')[2:]

    data = ''.join(src_data + dst_data)
    data = bytearray.fromhex(data)

    header = int(header, base=16)
    last_packet = 0x01 & header
    sequence = header >> 1

    return sequence, last_packet, data


def get_data(interface: str, encryption_key: bytes, integrity_key: bytes) -> str:
    capture = pyshark.LiveCapture(interface=interface,
                                  monitor_mode=True,
                                  capture_filter=FILTER)

    while True:
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
                break

        # Pull out the data and pull out the MAC
        packets = sorted(packets.items())
        encrypted_data = b''.join([value for key, value in packets[:-2]])
        mac_data = b''.join([value for key, value in packets[-2:]])

        LOGGER.debug("Encrypted data: %s", encrypted_data)
        LOGGER.debug("MAC: %s", mac_data)

        if mac_data == utils.hash_message(key=integrity_key,
                                          message=encrypted_data):
            break
        else:
            LOGGER.warning("MAC is different -- the data is invalid. Retrying...")

    data = utils.decrypt_message(key=encryption_key,
                                 message=encrypted_data)
    LOGGER.debug("Data: %s", data)
    return data


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('interface')
    args = parser.parse_args()

    with open('config.json') as f:
        config = json.load(f)

    data = get_data(args.interface,
                    config['encryption_key'].encode(),
                    config['integrity_key'].encode())
    print(data)
