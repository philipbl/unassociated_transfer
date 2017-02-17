import argparse
import json
import logging

from receive import get_data


def main(interface: str) -> None:
    # Get keys
    with open('config.json') as f:
        config = json.load(f)

    # Get data
    data = get_data(args.interface,
                    config['encryption_key'].encode(),
                    config['integrity_key'].encode())

    print(data)
    data = data.encode()
    print(data)

    ssid, password = data.split(':')

    print("SSID:", ssid)
    print("Password", password)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('interface')
    args = parser.parse_args()

    main(args.interface)

