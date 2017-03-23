from __future__ import generators, division, print_function, with_statement
import argparse
import json
import logging

from receive import receive


def main(interface):
    # Get keys
    with open('config.json') as f:
        config = json.load(f)

    # Get data
    data = receive(args.interface,
                   config['encryption_key'].encode(),
                   config['integrity_key'].encode())

    data = data.decode()
    data = data.replace('\0', '')

    print(data)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('interface')
    args = parser.parse_args()

    main(args.interface)

