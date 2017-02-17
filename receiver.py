import argparse
import logging

import pyshark

import utils

logging.basicConfig(level=logging.DEBUG)
LOGGER = logging.getLogger(__name__)

FILTER = "wlan[4] == 0x33 and wlan[5] == 0x33 and wlan[16] == 0xfe"


def process_packet(packet):
    src = packet.wlan.sa
    dst = packet.wlan.da

    sequence, *src_data = src.split(':')[1:]
    dst_data = dst.split(':')[2:]

    data = ''.join(src_data + dst_data)
    data = bytearray.fromhex(data)

    sequence = int(sequence, base=16)

    return sequence, data


def get_data(interface):
    capture = pyshark.LiveCapture(interface=interface,
                                  monitor_mode=True,
                                  capture_filter=FILTER)

    while True:
        packets = {}
        for packet in capture.sniff_continuously():
            sequence, data = process_packet(packet)

            if sequence not in packets:
                LOGGER.debug("Received %s", sequence)
                packets[sequence] = data

            # TODO: Fix this
            if len(packets) == 4:
                break

        # Pull out the data and pull out the MAC
        packets = sorted(packets.items())

        encrypted_data = b''.join([value for key, value in packets[:-2]])
        mac_data = b''.join([value for key, value in packets[-2:]])

        LOGGER.debug("Encrypted data: %s", encrypted_data)
        LOGGER.debug("MAC: %s", mac_data)

        if mac_data == utils.hash_message(key=b'key', message=encrypted_data):
            break
        else:
            LOGGER.warning("MAC is different -- the data is invalid. Retrying...")

    data = utils.decrypt_message(key=b'1234567894123456',
                                 message=encrypted_data)
    LOGGER.debug("Data: %s", data)
    return data


def get_wifi_information(data):
    LOGGER.debug("Converting to SSID and password")

    # TODO: Remove padding

    # TODO: Split apart
    return None, None


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('interface')
    args = parser.parse_args()

    ssid, password = get_wifi_information(get_data(args.interface))

    print("SSID:", ssid)
    print("Password:", password)
