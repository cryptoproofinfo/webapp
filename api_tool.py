from os import environ
from urllib import urlencode
from sys import argv, exit
from time import sleep
from urllib2 import Request, urlopen, URLError
from M2Crypto import RSA
from binascii import unhexlify
import json
#from pycoin.key.validate import is_public_bip32_valid

# Variables
xpubkeys = environ.get('XPUBKEYS')
sigs = environ.get('SIGS')
if not xpubkeys or sigs:
    xpubkeys = False
    sigs = False

mode = argv[1]
info = argv[2] if len(argv) > 2 else False

if not xpubkeys:
    print 'invalid xpubkey value'
    exit()

if not sigs:
    print 'invalid sigs value'
    exit()

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
            path_crt = 'cert.key'
            encoded_str = result['message']

            private_crt = RSA.load_key(path_crt)
            decrypted_str = private_crt.private_decrypt(unhexlify(encoded_str), RSA.pkcs1_padding)

        data.update(dict(info=decrypted_str))

data = urlencode(data)
sleep(1)
print get_data(address, data)
