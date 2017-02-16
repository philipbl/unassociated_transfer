import argparse

import pyshark

FILTER = "wlan[4] == 0x33 and wlan[5] == 0x33 and wlan[16] == 0xfe"
ALL_DATA = ""


def process_packet(packet):
    global ALL_DATA

    src = packet.wlan.sa
    dst = packet.wlan.da

    sequence, *src_data = src.split(':')[1:]
    dst_data = dst.split(':')[2:]

    data = ''.join(src_data + dst_data)
    data = bytearray.fromhex(data).decode()

    ALL_DATA += data
    print(ALL_DATA)


def get_wifi_information(interface):
    print(interface)
    capture = pyshark.LiveCapture(interface=interface,
                                  monitor_mode=True,
                                  capture_filter=FILTER)
    capture.set_debug()
    capture.apply_on_packets(process_packet)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('interface')
    args = parser.parse_args()

    get_wifi_information(args.interface)
