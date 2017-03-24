from __future__ import generators, division, print_function, with_statement
import argparse
import json
import logging

from send import send
import utils


def main(ssid, password, send_flag, loss):
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
         config['integrity_key'].encode(),
         send_flag=send_flag,
         possible_loss=loss)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Send WiFi SSID and password to unassociated client')
    parser.add_argument('ssid')
    parser.add_argument('password')
    parser.add_argument('-s', '--send-flag', type=int, choices=[0, 1], default=0,
                        help='Flag used to distinguish between transmissions.')
    parser.add_argument('-l', '--loss', choices=utils.FEC_LOSS, default=utils.FEC_LOSS[0],
                        help='How much loss can be tolerated.')

    args = parser.parse_args()
    main(args.ssid, args.password, args.send_flag, args.loss)
