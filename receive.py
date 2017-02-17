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


def get_data(interface: str, encryption_key: bytes, integrity_key: bytes) -> str:
    for packets in get_packets(interface):
        packets = sorted(packets.items())

        # Get all of the data from the packets
        iv_data = b''.join([value for key, value in packets[:2]])
        global_sequence_data = b''.join([value for key, value in packets[2:3]])
        encrypted_data = b''.join([value for key, value in packets[3:-2]])
        mac_data = b''.join([value for key, value in packets[-2:]])

        LOGGER.debug("IV: %s", iv_data)
        LOGGER.debug("Global sequence number: %s", global_sequence_data)
        LOGGER.debug("Encrypted data: %s", encrypted_data)
        LOGGER.debug("MAC: %s", mac_data)

        if mac_data != utils.hash_message(key=integrity_key,
                                          message=global_sequence_data + encrypted_data):
            LOGGER.warning("MAC is different -- the data is invalid. Retrying...")
            continue

        data = utils.decrypt_message(key=encryption_key,
                                     iv=iv_data,
                                     message=encrypted_data)
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
