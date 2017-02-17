import argparse

import pyshark

import utils

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


def get_wifi_information(interface):
    print(interface)
    capture = pyshark.LiveCapture(interface=interface,
                                  monitor_mode=True,
                                  capture_filter=FILTER)
    capture.set_debug()

    packets = {}
    for packet in capture.sniff_continuously():
        sequence, data = process_packet(packet)

        if sequence not in packets:
            print("Received", sequence)
            packets[sequence] = data

        if len(packets) == 4:
            break

    print(packets)

    # Pull out the data and pull out the MAC
    packets = sorted(packets.items())

    encrypted_data = b''.join([value for key, value in packets[:-2]])
    hash_data = b''.join([value for key, value in packets[-2:]])

    print(encrypted_data)
    print(hash_data)

    if hash_data != utils.hash_message(key=b'key', message=encrypted_data):
        print("MAC is different. The data is invalid")
        # TODO: Try again
        return

    data = utils.decrypt_message(key=b'1234567894123456',
                                 message=encrypted_data)
    print(data)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('interface')
    args = parser.parse_args()

    get_wifi_information(args.interface)
