from urllib import urlencode
from sys import argv, exit
from time import sleep
from urllib2 import Request, urlopen, URLError
from M2Crypto import RSA
from binascii import unhexlify
import json

# Variables
xpubkeys = 'xpub661MyMwAqRbcG4rmiyGLd7guhf2Gdy2FvRQrQk1hSSSTR56BfMFmR8myWyYNkct8jfQ4UR3cAHHdcT1b38aZYvyhTxQLa4bCoyZpEqUhB3g'
sigs = '0'
mode = argv[1]
info = argv[2] if len(argv) > 2 else False

def get_data(url, data):
    request = Request(url, data)
    response = urlopen(request)

    data = json.load(response)
    response.close()
    return data

# Check for valid url
l = ('search', 'url', 'index', 'withdraw', 'verify', 'account', 'login_history', 'subkey_activity', 'transaction_history')
if not mode in l:
    print dict(status=False, message='url error')
    exit()

if len(argv) > 3:
    raise TypeError('input expected at most 2 arguments, got %s' % len(argv))

# Set variables, identify relevant code block and print server response
address = 'https://cryptoproof.info/api/%s/' % mode

# 1 argument
if mode == 'search':
    data = dict(info=info)

else:
    data = dict(xpubkeys=xpubkeys, sigs=sigs)

    if mode in ['url', 'index', 'withdraw']:
        data.update(dict(info=info))

    # 2 arguments
    if mode == 'verify':
        encoded_data = urlencode(data)
        result = get_data(address, encoded_data)

        if not result['status']:
            print result
            exit()

        else:
            path_crt = '/home/derrend/django_studio/cryptoproof/ssl/cryptoproof.key'
            encoded_str = result['message']

            private_crt = RSA.load_key(path_crt)
            decrypted_str = private_crt.private_decrypt(unhexlify(encoded_str), RSA.pkcs1_padding)

        data.update(dict(info=decrypted_str))

data = urlencode(data)
sleep(1)
print get_data(address, data)
