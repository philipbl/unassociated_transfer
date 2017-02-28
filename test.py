from __future__ import generators, division, print_function, with_statement
import argparse
import logging
import random
import time


parser = argparse.ArgumentParser(description='Test unassociated WiFi protocol')
parser.add_argument('type', choices=['sender', 'receiver'])
parser.add_argument('amount', type=int)
parser.add_argument('--interface')
args = parser.parse_args()

encryption_key = '38B93,@//a3*==33'
integrity_key = '8?9@^;8#C2269=%E'

if args.type == 'sender':
    import string
    from send import send

    with open('send.txt', 'w') as f:
        for x in range(args.amount):
            data = ''.join([random.choice(string.letters) for i in range(16 * random.randint(1, 6))])
            f.write(data + '\n')
            send(data, encryption_key, integrity_key, send_flag=x % 2, possible_loss=.5)
            time.sleep(5)

elif args.type == 'receiver':
    from receive import receive

    if args.interface is None:
        print("Must provide --interface when in receiver mode")
        exit()

    with open('receive.txt', 'w') as f:
        for x in range(args.amount):
            data = receive(args.interface, encryption_key, integrity_key)
            f.write(data + '\n')


