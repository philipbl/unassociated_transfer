import argparse
import json
import logging

from send import send


def main(ssid: str, password: str) -> None:
    # Get keys
    with open('config.json') as f:
        config = json.load(f)

    # Make sure data is divisible by 16
    data = '{}:{}'.format(ssid, password)

    # TODO: Be smarter about padding
    padding = 16 - (len(data) % 16)
    data = data + '\0' * padding

    send(data.encode(),
         config['encryption_key'].encode(),
         config['integrity_key'].encode())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Send WiFi SSID and password to unassociated client')
    parser.add_argument('ssid')
    parser.add_argument('password')

    args = parser.parse_args()

    main(args.ssid, args.password)
