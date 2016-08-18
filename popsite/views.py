from __future__ import print_function
from django.shortcuts import render_to_response, redirect
from django.http import JsonResponse, HttpResponse
from django.core.context_processors import csrf
from django import forms
from django.template import RequestContext
from django.views.decorators.csrf import csrf_exempt

from popsite.models import account
from popsite.models import subkey
from popsite.models import transaction
from popsite.models import access
from popsite.models import payment

from django.core.cache import cache as rdb
from django.core.validators import URLValidator

from popsite.forms import CaptchaTestForm
from popsite.forms import AccountsForm
from popsite.forms import SearchForm, RegistrationForm
from popsite.forms import VerificationForm
from popsite.forms import RefundForm

from tables import LoginTable, TransactionTable, SubkeyTable
from popsite.tasks import create_keys

from blockchain.exchangerates import get_ticker     # remote
from blockchain.pushtx import pushtx                # remote
from blockchain.blockexplorer import get_address    # remote

from pycoin.key.validate import is_public_bip32_valid, is_address_valid
from pycoin.key.Key import Key
from pycoin.tx.tx_utils import create_signed_tx
from pycoin.tx import Spendable
from pycoin.serialize import h2b

from binascii import hexlify
from datetime import datetime
from decimal import Decimal
from hashlib import sha256
from M2Crypto import RSA, X509
from random import choice
from re import match
from string import ascii_letters, digits, maketrans
from ssl import PROTOCOL_TLSv1, PROTOCOL_SSLv23, PROTOCOL_SSLv3 #, PROTOCOL_SSLv2
from ssl import get_server_certificate              # remote
from urllib2 import urlopen                         # remote
import json
import csv
#from pycoin.tx.pay_to import ScriptMultisig, address_for_pay_to_script
#from django.core.exceptions import ValidationError
#from pycoin.services import spendables_for_address  # remote

#region Variables
cryptoproof_deposit_key_str = 'secret_xpubkey_string'
cryptoproof_deposit_key_obj = Key.from_text(cryptoproof_deposit_key_str)
cryptoproof_payment_key_str = 'secret_xprikey_string'
cryptoproof_payment_key_obj = Key.from_text(cryptoproof_payment_key_str)
transaction_code = 'secret_random_string'

api_code = 'secret_api_string'
hostname = 'blockchain.info'
#cryptoproof_addr = '17NKQddUT443ZweQAtDvcQNC9oso2j9Zcv'

invalid_xpub = 'Invalid extended public key(s)'
invalid_addr = 'Invalid bitcoin address'
error_msg = 'Something bad happened, please try again later'
split_string = 'xpub661MyMwAqRbc'

network_transaction_fee = Decimal('0.0001')
cost_per_key = Decimal('0.01')
free_keys = 10
hard_index_limit = 10000
minimum_confirmations = 3
sigs_limit = 15
string_length = 32
session_expiry_time = 600  # 10 minutes
#endregion
# Snippet from pycoin.services, received error when imported from library
def spendables_for_address(bitcoin_address):
    """Snippet from pycoin.services, received error when imported from library
    Gets spendables objects for address

    Args:
        bitcoin_address (str, required): Mainnet Bitcoin address

    Returns:
        spendables (list): List of unspent inputs
    """
    URL = "http://blockchain.info/unspent?active=%s" % bitcoin_address
    r = json.loads(urlopen(URL).read().decode("utf8"))
    spendables = []
    for u in r["unspent_outputs"]:
        coin_value = u["value"]
        script = h2b(u["script"])
        previous_hash = h2b(u["tx_hash"])
        previous_index = u["tx_output_n"]
        spendables.append(Spendable(coin_value, script, previous_hash, previous_index))
    return spendables

# Test if https url and attempt certificate extraction          #REMOTE
def get_cypher(submitted_url):
    """REMOTE, Test if https url, attempt certificate extraction and encrypt random string

    Args:
        submitted_url (str, required): http(s) URL

    Returns:
        spendables (list): List of unspent inputs
    """
    if match('^https', submitted_url):
        modified_url = submitted_url.replace('https://', '').strip('/')

        cert = False
        for i in [PROTOCOL_TLSv1, PROTOCOL_SSLv23, PROTOCOL_SSLv3]:
            try:
                cert = get_server_certificate((modified_url, 443), ssl_version=i)
                break
            except:
                pass

        if cert:
            vstring = ''.join([choice(ascii_letters + digits) for _ in xrange(32)])

            cert509 = X509.load_cert_string(cert)
            rsa = cert509.get_pubkey().get_rsa()
            return hexlify(rsa.public_encrypt(vstring, RSA.pkcs1_padding)), vstring

    return False, False

# Set or unset session variables for certificate if available   #REMOTE
def set_cypher_session(request, submitted_url):
    """Save verification strings to session cache

    Args:
        request (request object, required): request object
        submitted_url (str, required): http(s) URL
    """
    if not request.session.get('cert_check'):
        cypher = get_cypher(submitted_url)
        request.session['encrypted_str'] = cypher[0]
        request.session['decrypted_str'] = cypher[1]
        request.session['cert_check'] = True

# Return decimal whole btc balance                              #REMOTE
def addr_bal(address):
    """Retrieves lowest balance up to minimum confirmations

    Args:
        address (str, required): Mainnet Bitcoin address

    Returns:
        unconfirmed_balance (Decimal): Address balance at 0 confirmations
        confirmed_balance (Decimal): Address balance at minimum confirmations
    """
    # Blockchain.info returns positive confirmed balance after withdrawl so unconfirmed balance is needed
    confirmed_balance = Decimal('{0:.8}'.format(urlopen('https://%s/q/addressbalance/%s?confirmations=%s&api_code=%s' % (hostname, address, minimum_confirmations, api_code)).read()))
    unconfirmed_balance = Decimal('{0:.8}'.format(urlopen('https://%s/q/addressbalance/%s?confirmations=%s&api_code=%s' % (hostname, address, 0, api_code)).read()))

    if unconfirmed_balance < confirmed_balance:
        return unconfirmed_balance / 100000000

    return confirmed_balance / 100000000

def get_bitcoin_price(request):
    """Check for updated Bitcoin price

    Args:
        request (request object, required): request object

    Returns:
        price (Decimal): Bitcoin price
        False (Bool): False
    """
    price = rdb.get('price')
    if not price:
        try:
            price = Decimal('{0:.2f}'.format(get_ticker()['USD'].p15min))
            rdb.set('price', price, timeout=600)
            return price
        except:
            request.session['error_msg'] = error_msg
            return False
    return price

# Retrieve IP address of client
def get_client_ip(request):
    """Get client ip address

    Args:
        request (request object, required): request object

    Returns:
        request.META.get('REMOTE_ADDR') (str): Client ip address
        x_forwarded_for.split(',')[0] (str): Client ip address
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]

    return request.META.get('REMOTE_ADDR')

def set_pass_token(request, destination):
    """Set pass token in request cache for adjacent views access

    Args:
        request (request object, required): request object
        destination (str, required): varification token for webpage access
    """
    request.session[u'pass_token'] = destination
    request.session.set_expiry(session_expiry_time)

def verify_pass_token(request, source):
    """Check if verify cache token matches client string

    Args:
        request (request object, required): request object
        source (str, required): submitted verification string

    Returns:
        True (bool): True
    """
    if not request.session.get('pass_token') == source:
        return False
    del request.session['pass_token']
    return True

def details(request):  #, pubkey_json, sigs):
    """Perform checks on public key(s) and return dictionary of account values

    Args:
        request (request object, required): request object
        pubkey_json (str, required): submitted verification string
        sigs (str, required): number of signatories

    Returns:
        locals (dict): Dictionary of account valuew
    """
    # Check api request limit
    if rdb.get(get_client_ip(request)):
        return dict(status=False, message='request limit reached')
    rdb.set(get_client_ip(request), True, timeout=1)

    # Check for valid sig number
    try:
        sigs = int(request.session['sigs']) if request.session.get('sigs') else int(request.POST['sigs'])
    except:
        return dict(status=False, message='invalid sigs field')

    # Check for valid sig limit
    if sigs > sigs_limit:
        return dict(status=False, message='invalid sigs limit')

    # Create xpubkey string list
    xpubkey_str_lst = []
    for i in request.session['xpubkeys'].split(split_string) if request.session.get('xpubkeys') else request.POST['xpubkeys'].split(split_string):
        xpubkey_str_lst.append(split_string + i)
    del xpubkey_str_lst[0]

    # Adjust sigs number
    if len(xpubkey_str_lst) < 2:
        sigs = 0

    # Check for conflicting sigs number
    if sigs > len(xpubkey_str_lst):
        return dict(status=False, message='number of sigs cannot be greater than number of submitted xpubkeys')

    # Check valid pubkeys
    for i in xpubkey_str_lst:
        if not is_public_bip32_valid(i):
            return dict(status=False, message=invalid_xpub)

    # Check unique pubkeys
    if not len(xpubkey_str_lst) == len(set(xpubkey_str_lst)):
        return dict(status=False, message='Pubkeys must be unique')

    # Create xpubkey object list
    xpubkey_obj_lst = []
    for i in xpubkey_str_lst:
        xpubkey_obj_lst.append(Key.from_text(i))

    # Make sure list is not empty
    if len(xpubkey_obj_lst) < 1:
            return dict(status=False, message='xpubkey object error')

    for i in xpubkey_obj_lst:
        # Test if depth and child index are beyond maximum
        if i.child_index() > 2146483647:
            return dict(status=False, message='xpubkey child index cannot be more than 2146483647')

        if i.tree_depth() > 255:
            return dict(status=False, message='xpubkey tree depth cannot be more than 255')

        # Test if key balance is zero (optional restriction)
        try:
            addr_obj = get_address(i.address())
        except:
            return dict(status=False, message=error_msg)

        if not addr_obj.total_received == 0:
            return dict(status=False, message='public key received balance cannot be non-zero')

    if len(xpubkey_obj_lst) > 1 and sigs < 1:
        return dict(status=False, message='sigs cannot be zero for multiple keys')

    hashone = sha256(''.join(xpubkey_str_lst) + str(sigs)).hexdigest()
    hashtwo = sha256(hashone).hexdigest()

    # Get client subkey object
    string_obj = maketrans('', '')
    translation = string_obj.translate(string_obj, digits)
    translated = str(hashone).translate(string_obj, translation)

    # Check that subkey path is at least 3 levels deep
    if not len(translated) > 18:
        return dict(status=False, message='hashed address of the pubkey(s) contains less than 9 digits and cannot be used for security reasons,\nplease use a different pubkey')

    # Get path to private key
    key_path = ''
    limit = len(translated) / 9
    c = 0
    while c <= limit:
        key_path += '%s/' % translated[c*9:(c+1)*9]
        c += 1

    request.session['path'] = key_path.strip('/')
    subkey_obj = cryptoproof_deposit_key_obj.subkey_for_path(key_path.strip('/'))
    account_record_qset = account.objects.filter(hashtwo=hashtwo)

    status = True
    return locals()

def get_signed_tx(request, cryptoproof_payment_key_obj, account_record):
    """Verify signed transaction

    Args:
        request (request object, required): request object
        cryptoproof_payment_key_obj (xpubkey_obj, required): payment address key
        account_record (access object, required): account record

    Returns:
        locals (dict): Dictionary of account valuew
    """
    def create_tx(l):
        """Create signed transaction

        Args:
            l (list, required): Contains details to build signed object

        Returns:
            create_signed_tx (signed transaction object): signed transaction
        """
        return create_signed_tx(spendables,
                                l,
                                wifs=[Key.from_text(request.session.get('cryptoproof_subkey_str')).wif()],
                                fee='standard')

    # Get spendables
    try:
        spendables = spendables_for_address('%s&api_code=%s&confirmations=%s' % (request.session.get('deposit_address'), api_code, minimum_confirmations))
    except:
        return False

    if not request.POST.get('refund_address'):
        # Reserve transaction
        try:
            return create_tx([(cryptoproof_payment_key_obj.subkey(account_record.id).address(), int(account_record.spent * 100000000)),
                              Key.from_text(request.session.get('cryptoproof_subkey_str')).address()])
        except:
            return create_tx([cryptoproof_payment_key_obj.subkey(account_record.id).address()])

    # Withdrawl request
    if account_record.spent > 0:
        try:
            return create_tx([(cryptoproof_payment_key_obj.subkey(account_record.id).address(), int(account_record.spent * 100000000)),
                              request.POST.get('refund_address')])
        except:
            return create_tx([cryptoproof_payment_key_obj.subkey(account_record.id).address()])  # is this necessary?
    else:
        return create_tx([request.POST.get('refund_address')])


#######
# API #
#######
## DICTIONARIE ##
# 1 args
@csrf_exempt
def api_search(request):  #, address_json):
    if request.POST:
        # Check api request limit
        if rdb.get(get_client_ip(request)):
            response_json = dict(status=False, message='request limit reached')
            return JsonResponse(response_json)
        rdb.set(get_client_ip(request), True, timeout=1)

        # Test if string is valid BTC address and search database for match if so
        if not is_address_valid(request.POST['info']):
            response_json = dict(status=False, message='invalid bitcoin address')
            return JsonResponse(response_json)

        # If key_result exists, increment result number, get account record
        key_result = subkey.objects.filter(hash=sha256(request.POST['info']).hexdigest())
        if not key_result.exists():
            response_json = dict(status=False, message='address not found')
            return JsonResponse(response_json)

        key_record = key_result[0]
        key_record.hits += 1
        key_record.last_accessed = datetime.now()
        key_record.save()

        ac_obj = account.objects.filter(id=key_record.account_id)[0]
        message = dict(compressed_address=request.POST['info'],
                       associated_url=ac_obj.url,
                       verified_status=ac_obj.verified_status,
                       hits=key_record.hits)

        response_json = dict(status=True, message=message)
        return JsonResponse(response_json)

@csrf_exempt
def api_process_transactions(request):
    if request.POST:
        if request.POST.get('transaction_code') == transaction_code:

            payment_obj_qset = payment.objects.all()
            if payment_obj_qset.exists():

                for i in payment_obj_qset:
                    pushtx(i.signed_tx)

                    account_record = account.objects.filter(id=i.account_id)[0]
                    account_record.spent = 0
                    account_record.save()
                    i.delete()

                response_json = dict(status=True)
                return JsonResponse(response_json)

# 2 args
@csrf_exempt
def api_url(request):  #, pubkey_json, sigs):
    if request.POST:
        # Validate URL
        url = request.POST['info'].replace('www.', '')
        validator = URLValidator(schemes=['http', 'https'])
        try:
            validator(url)
        except:
            response_json = dict(status=False, message='url string error', url=url)
            return JsonResponse(response_json)

        # Get account details dictionary
        details_dict = details(request)  #, pubkey_json, sigs)
        if not details_dict['status']:
            response_json = dict(status=False, message=details_dict['message'])
            return JsonResponse(response_json)

        # Check account exists
        if not details_dict['account_record_qset'].exists():
            response_json = dict(status=False, message='account record does not exist')
            return JsonResponse(response_json)
        account_record = details_dict['account_record_qset'][0]

        # exit if url is unchanged
        if account_record.url == url:
            response_json = dict(status=False, message='url string unchanged')
            return JsonResponse(response_json)

        account_record.verified_status = False
        account_record.url = url
        account_record.save()

        access.objects.create(account_id=account_record.id, ipaddress=get_client_ip(request), interface='api_url').save()
        response_json = dict(status=True)
        return JsonResponse(response_json)

@csrf_exempt
def api_verify(request):  #, pubkey_json, sigs):
    if request.POST:
        # Get account details dictionary
        details_dict = details(request)  #, pubkey_json, sigs)
        if not details_dict['status']:
            response_json = dict(status=False, message=details_dict['message'])
            return JsonResponse(response_json)

        # Check account exists
        if not details_dict['account_record_qset'].exists():
            response_json = dict(status=False, message='account record does not exist')
            return JsonResponse(response_json)
        account_record = details_dict['account_record_qset'][0]

        decrypted_str = request.POST.get('info')
        if not decrypted_str:
            # Check not already verified
            if account_record.verified_status:
                response_json = dict(status=False, message='account already verified')
                return JsonResponse(response_json)

            # Validate URL
            validator = URLValidator(schemes=['https'])
            try:
                validator(account_record.url)
            except:
                response_json = dict(status=False, message='url string error')
                return JsonResponse(response_json)

            # Get cypher for url
            cypher = get_cypher(account_record.url)
            encrypted_str = cypher[0]
            decrypted_str = cypher[1]

            # Save decrypted string as key for 30 seconds to redis cache, value as True
            rdb.set(''.join(details_dict['xpubkey_str_lst']) + decrypted_str, True, timeout=30)

            access.objects.create(account_id=account_record.id, ipaddress=get_client_ip(request), interface='api_verify_get').save()
            response_json = dict(status=True, message=encrypted_str)
            return JsonResponse(response_json)

        # Check valid string
        if not rdb.get(''.join(details_dict['xpubkey_str_lst']) + decrypted_str):
            response_json = dict(status=False, message='invalid string')
            return JsonResponse(response_json)

        # Get record and set verified status
        account_record.verified_status = True
        account_record.save()

        access.objects.create(account_id=account_record.id, ipaddress=get_client_ip(request), interface='api_verify_post').save()

        response_json = dict(status=True)
        return JsonResponse(response_json)

@csrf_exempt
def api_account(request):  #, pubkey_json, sigs, web_ui=False):
    if request.POST:
        # Get account details dictionary

        details_dict = details(request)  #, pubkey_json, sigs)
        if not details_dict['status']:
            response_json = dict(status=False, message=details_dict['message'])
            return JsonResponse(response_json)

        # Check account exists
        if not details_dict['account_record_qset'].exists():
            response_json = dict(status=False, message='account record does not exist')
            return JsonResponse(response_json)
        account_record = details_dict['account_record_qset'][0]

        # Get current bitcoin price
        price = get_bitcoin_price(request)
        if not price:
            return dict(status=False, message='blockchain price api failed')

        # Get balance
        try:
            balance = addr_bal(details_dict['subkey_obj'].address()) - account_record.spent
        except:
            return dict(status=False, message='blockchain balance api failed')

        # Calculate variables and initialise dictionary
        credit = Decimal('{0:.2f}'.format(price * balance)) - Decimal('0.01')
        if credit < 0:
            credit = Decimal('{0:.2f}'.format(0))

        affordable_keys = int(credit / cost_per_key)
        upper_index = affordable_keys + account_record.index_limit

        remaining_key_allowance = free_keys - account_record.index_limit
        if not remaining_key_allowance <= 0:
            upper_index += remaining_key_allowance
        else:
            remaining_key_allowance = 0

        account_record_dict = details_dict['account_record_qset'].values()[0]
        # if not web_ui:
        del account_record_dict['hashtwo']
        del account_record_dict['spent']
        del account_record_dict['id']

        account_record_dict.update(dict(deposit_address=details_dict['subkey_obj'].address(),
                                        credit=credit,
                                        available_keys=affordable_keys,
                                        upper_index=upper_index,
                                        free_keys=remaining_key_allowance,
                                        balance=balance,
                                        price=price))

        access.objects.create(account_id=account_record.id, ipaddress=get_client_ip(request), interface='api_account').save()
        return JsonResponse(dict(status=True, message=account_record_dict))

## LIST OF DICTIONARIES ##
@csrf_exempt
def api_login_history(request):  #, pubkey_json, sigs):
    if request.POST:
        # Get account details dictionary
        details_dict = details(request)  #, pubkey_json, sigs)
        if not details_dict['status']:
            response_json = dict(status=False, message=details_dict['message'])
            return JsonResponse(response_json)

        # Check account exists
        if not details_dict['account_record_qset'].exists():
            response_json = dict(status=False, message='account record does not exist')
            return JsonResponse(response_json)
        account_record = details_dict['account_record_qset'][0]

        # Create and return json response
        l = []
        for i in access.objects.filter(account_id=account_record.id).order_by('-id'):
            l.append(dict(date=str(i.id), ip_address=i.ipaddress, interface=i.interface.encode('utf-8')))

        access.objects.create(account_id=account_record.id, ipaddress=get_client_ip(request), interface='api_login_history').save()
        response_json = dict(status=True, message=l)
        return JsonResponse(response_json)

@csrf_exempt
def api_subkey_activity(request):  #, pubkey_json, sigs):
    if request.POST:
        # Get account details dictionary
        details_dict = details(request)  #, pubkey_json, sigs)
        if not details_dict['status']:
            response_json = dict(status=False, message=details_dict['message'])
            return JsonResponse(response_json)

        # Check account exists
        if not details_dict['account_record_qset'].exists():
            response_json = dict(status=False, message='account record does not exist')
            return JsonResponse(response_json)
        account_record = details_dict['account_record_qset'][0]

        # Create and return json response
        l = []
        for i in subkey.objects.filter(account_id=account_record.id).filter(hits__gt=0).order_by('-last_accessed'):
            l.append(dict(date=str(i.last_accessed), subkey_index=i.subkey_index, hits=i.hits))

        access.objects.create(account_id=account_record.id, ipaddress=get_client_ip(request), interface='api_subkey_activity').save()
        response_json = dict(status=True, message=l)
        return JsonResponse(response_json)

@csrf_exempt
def api_transaction_history(request):  #, pubkey_json, sigs):
    if request.POST:
        # Get account details dictionary
        details_dict = details(request)  #, pubkey_json, sigs)
        if not details_dict['status']:
            response_json = dict(status=False, message=details_dict['message'])
            return JsonResponse(response_json)

        # Check account exists
        if not details_dict['account_record_qset'].exists():
            response_json = dict(status=False, message='account record does not exist')
            return JsonResponse(response_json)
        account_record = details_dict['account_record_qset'][0]

        # Create and return json response
        l = []
        for i in transaction.objects.filter(account_id=account_record.id).order_by('-id'):
            l.append(dict(date=str(i.id), btc_price=i.btc_price, btc_amount=i.btc_amount))

        access.objects.create(account_id=account_record.id, ipaddress=get_client_ip(request), interface='api_transaction_history').save()
        response_json = dict(status=True, message=l)
        return JsonResponse(response_json)

# 3 args
@csrf_exempt
def api_index(request):  #, pubkey_json, sigs, submitted_index_limit):
    if request.POST:
        # Get account details dictionary
        details_dict = details(request)  #, pubkey_json, sigs)
        if not details_dict['status']:
            response_json = dict(status=False, message=details_dict['message'])
            return JsonResponse(response_json)

        # Check account exists
        if not details_dict['account_record_qset'].exists():
            response_json = dict(status=False, message='account record does not exist')
            return JsonResponse(response_json)
        account_record = details_dict['account_record_qset'][0]

        # Get current bitcoin price
        price = get_bitcoin_price(request)
        if not price:
            return dict(status=False, message='blockchain price api failed')

        # Get balance
        try:
            balance = addr_bal(details_dict['subkey_obj'].address()) - account_record.spent
        except:
            return dict(status=False, message='blockchain balance api failed')

        # Calculate variables and initialise dictionary
        credit = Decimal('{0:.2f}'.format(price * balance)) - Decimal('0.01')
        if credit < 0:
            credit = Decimal('{0:.2f}'.format(0))

        affordable_keys = int(credit / cost_per_key)
        upper_index = affordable_keys + account_record.index_limit
        submitted_index_limit = int(request.POST['info'])
        extra_keys = submitted_index_limit - account_record.index_limit

        remaining_key_allowance = free_keys - account_record.index_limit
        if remaining_key_allowance < 1:
            remaining_key_allowance = 0

        # upper_index = details_dict['affordable_keys'] + details_dict['remaining_key_allowance']
        if upper_index < 1:
            response_json = dict(status=False, message='insufficient credit')
            return JsonResponse(response_json)

        # Check submitted limit is not greater than allowed limit or less than 1
        if submitted_index_limit > upper_index or submitted_index_limit < 1:
            response_json = dict(status=False, message='index limit invalid')
            return JsonResponse(response_json)

        # Check for extra keys
        if extra_keys < 1:
            response_json = dict(status=False, message='index limit unchanged')
            return JsonResponse(response_json)

        chargable_keys = extra_keys - remaining_key_allowance
        if not chargable_keys < 1:  # Charge
            btc_spent = Decimal("{0:.8f}".format((chargable_keys * cost_per_key) / price))

            account_record.spent += btc_spent
            transaction.objects.create(account_id=account_record.id,
                                       btc_price=price,
                                       btc_amount=btc_spent).save()

        # Create child objects
        create_keys.delay(''.join(details_dict['xpubkey_str_lst']),
                          submitted_index_limit,
                          account_record.id,
                          account_record.index_limit,
                          request.POST['sigs'])

        account_record.index_limit = submitted_index_limit
        account_record.save()

        # Create and save transaction for spent funds
        if account_record.spent > network_transaction_fee:
            try:
                spendables = spendables_for_address('%s&api_code=%s&confirmations=%s' % (details_dict['subkey_obj'].address(), api_code, minimum_confirmations))
            except:
                response_json = dict(status=False, message='pycoin spendables api failed')
                return JsonResponse(response_json)

            try:
                signed_tx = create_signed_tx(spendables,
                                             [(cryptoproof_payment_key_obj.subkey(account_record.id).address(), int(account_record.spent * 100000000)), details_dict['subkey_obj'].address()],
                                             wifs=[details_dict['subkey_obj'].wif()],
                                             fee='standard')
            except:
                signed_tx = create_signed_tx(spendables,
                                             [cryptoproof_payment_key_obj.subkey(account_record.id).address()],  #int(account_record.spent * 100000000)), details_dict['subkey_obj'].address()],
                                             wifs=[details_dict['subkey_obj'].wif()],
                                             fee='standard')

            #signed_tx = get_signed_tx(request, cryptoproof_payment_key_obj, account_record)
            #pushtx(signed_tx.as_hex())

            payment_obj_lst = payment.objects.filter(account_id=account_record.id)
            if payment_obj_lst.exists():
                payment_obj_lst.delete()
            payment.objects.create(account_id=account_record.id, signed_tx=signed_tx.as_hex()).save()

        access.objects.create(account_id=account_record.id, ipaddress=get_client_ip(request), interface='api_index').save()
        response_json = dict(status=True)
        return JsonResponse(response_json)

@csrf_exempt
def api_withdraw(request):  #, pubkey_json, sigs, address_json):
    if request.POST:
        # Check valid bitcoin address
        if not is_address_valid(request.POST['info']):
            response_json = dict(status=False, message='invalid bitcoin address')
            return JsonResponse(response_json)

        # Get account details dictionary
        details_dict = details(request)  #, pubkey_json, sigs)
        if not details_dict['status']:
            response_json = dict(status=False, message=details_dict['message'])
            return JsonResponse(response_json)

        # Check account exists
        if not details_dict['account_record_qset'].exists():
            response_json = dict(status=False, message='account record does not exist')
            return JsonResponse(response_json)

        account_record = details_dict['account_record_qset'][0]
        # Get balance
        try:
            balance = addr_bal(details_dict['subkey_obj'].address()) - account_record.spent
        except:
            response_json = dict(status=False, message='blockchain balance api failed')
            return JsonResponse(response_json)

        #balance = Decimal(request.session.get('balance'))
        if not balance > network_transaction_fee:
            response_json = dict(status=False, message='balance must be greater than %s' % network_transaction_fee)
            return JsonResponse(response_json)

        try:
            spendables = spendables_for_address('%s&api_code=%s&confirmations=%s' % (details_dict['subkey_obj'].address(), api_code, minimum_confirmations))
        except:
            response_json = dict(status=False, message='pycoin spendables api failed')
            return JsonResponse(response_json)

        # Create and push refund transaction
        if account_record.spent > 0:
            try:
                signed_tx = create_signed_tx(spendables,
                                             [(cryptoproof_payment_key_obj.subkey(account_record.id).address(), int(account_record.spent * 100000000)), request.POST['info']],
                                             wifs=[details_dict['subkey_obj'].wif()],
                                             fee='standard')
            except:
                signed_tx = create_signed_tx(spendables,
                                             [cryptoproof_payment_key_obj.subkey(account_record.id).address()],
                                             wifs=[details_dict['subkey_obj'].wif()],
                                             fee='standard')
        else:
            signed_tx = create_signed_tx(spendables, [request.POST['info']],
                                         wifs=[details_dict['subkey_obj'].wif()],
                                         fee='standard')

        try:
            pushtx(signed_tx.as_hex())
        except:
            response_json = dict(status=False, message='blockchain pushtx api failed')
            return JsonResponse(response_json)

        payment_obj_lst = payment.objects.filter(account_id=account_record.id)
        if payment_obj_lst.exists():
            payment_obj_lst.delete()

        transaction.objects.create(account_id=account_record.id,
                                   btc_price=000,
                                   btc_amount=balance - Decimal(str(signed_tx.fee() / float(100000000)))).save()

        account_record.spent = 0
        account_record.save()

        access.objects.create(account_id=account_record.id, ipaddress=get_client_ip(request), interface='api_withdraw').save()
        response_json = dict(status=True)
        return JsonResponse(response_json)


############
# DOWNLOAD #
############

def audit(request):
    # Create the HttpResponse object with the appropriate CSV header.
    timestamp = datetime.now().date().strftime('%d%m%Y') + datetime.now().time().strftime('%H%M%S')

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="cryptoproof_db_{}.csv"'.format(timestamp)

    writer = csv.writer(response)
    subkey_lst = subkey.objects.filter(hits__gt=0).order_by('?')

    if subkey_lst.exists():
        writer.writerow(['hashes', 'submissions'])

        for i in subkey_lst:
            writer.writerow([i.hash, i.hits])
    else:
        writer.writerow(['None'])

    return response

def login_history(request):
    try:
        # Create the HttpResponse object with the appropriate CSV header.
        timestamp = datetime.now().date().strftime('%d%m%Y') + datetime.now().time().strftime('%H%M%S')

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="cryptoproof_login_history_{}.csv"'.format(timestamp)

        writer = csv.writer(response)
        login_history = access.objects.filter(account_id=request.session['account_id']).order_by('-id')

        if login_history.exists():
            writer.writerow(['date', 'ip_address', 'interface'])

            for i in login_history:
                writer.writerow([i.id, i.ipaddress, i.interface])
        else:
            writer.writerow(['None'])

        return response

    except:
        request.session['error_msg'] = 'Session timeout'
        return redirect('login')

def subkey_activity(request):
    try:
        # Create the HttpResponse object with the appropriate CSV header.
        timestamp = datetime.now().date().strftime('%d%m%Y') + datetime.now().time().strftime('%H%M%S')

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="cryptoproof_subkey_activity_{}.csv"'.format(timestamp)

        writer = csv.writer(response)
        subkey_activity = subkey.objects.filter(account_id=request.session['account_id']).filter(hits__gt=0).order_by('-subkey_index')

        if subkey_activity.exists():
            writer.writerow(['last_accessed', 'subkey_index', 'hits'])

            for i in subkey_activity:
                writer.writerow([i.last_accessed, i.subkey_index, i.hits])
        else:
            writer.writerow(['None'])

        return response

    except:
        request.session['error_msg'] = 'Session timeout'
        return redirect('login')

def transaction_history(request):
    try:
        # Create the HttpResponse object with the appropriate CSV header.
        timestamp = datetime.now().date().strftime('%d%m%Y') + datetime.now().time().strftime('%H%M%S')

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="cryptoproof_transaction_history_{}.csv"'.format(timestamp)

        writer = csv.writer(response)
        transaction_history = transaction.objects.filter(account_id=request.session['account_id']).order_by('-id')

        if transaction_history.exists():
            writer.writerow(['date', 'btc_price', 'btc_amount'])

            for i in transaction_history:
                writer.writerow([i.id, i.btc_price, i.btc_amount])
        else:
            writer.writerow(['None'])

        return response

    except:
        request.session['error_msg'] = 'Session timeout'
        return redirect('login')


#########
# VIEWS #
#########

def search(request):
    #region POST
    if request.POST:
        if not verify_pass_token(request, 'search'):
            return redirect('search')

        if request.POST.get('camera'):
            request.session.update(camera=True)
            return redirect('search')

        if request.POST.get('to_login'):
            return redirect('login')
        #
        # if not is_address_valid(request.POST.get('address')):
        #     request.session['error_msg'] = invalid_addr
        #     return redirect('search')

        # results_dict = json.loads(api_search(request, request.POST.get('address')).getvalue())
        results_dict = json.loads(api_search(request).getvalue())
        if not results_dict['status']:
            request.session['error_msg'] = results_dict['message']
            return redirect('search')

        results_dict.update(csrf(request))
        return render_to_response('popsite/addinfo.html', results_dict['message'])
    #endregion
    #region GET
    # Clear and set initial session data
    html_dtc = dict()
    html_dtc.update(dict(camera=request.session.get('camera')))
    html_dtc.update(dict(error_msg=request.session.get('error_msg')))
    html_dtc.update(dict(form=SearchForm()))
    html_dtc.update(csrf(request))

    request.session.flush()
    set_pass_token(request, u'search')
    return render_to_response('popsite/search.html', html_dtc)
    #endregion

def login(request):
    #region POST
    if request.POST:
        # Check valid token
        if not verify_pass_token(request, 'login'):
            return redirect('login')

        # Check for button click
        if request.POST.get('to_search'):
            return redirect('search')

        # Check for empty strings
        if request.POST.get('xpubkeys') == '':
            request.session['error_msg'] = invalid_xpub
            return redirect('login')

        # Get account details dictionary
        details_dict = details(request)  #, request.POST['xpubkeys'], request.POST['sigs'])
        if not details_dict['status']:
            request.session['error_msg'] = details_dict['message']
            return redirect('login')

        # Populate session cache
        request.session['xpubkeys'] = ''.join(details_dict['xpubkey_str_lst'])
        request.session['sigs'] = details_dict['sigs']
        request.session['hahsone'] = details_dict['hashone']
        request.session['hashtwo'] = details_dict['hashtwo']
        request.session['deposit_address'] = details_dict['subkey_obj'].address()
        request.session['cryptoproof_subkey_str'] = details_dict['subkey_obj'].as_text(as_private=True)

        # Distinguish between login or register
        if not details_dict['account_record_qset'].exists():
            set_pass_token(request, u'register')
            return redirect('register')

        # Get account record and balance
        account_record = details_dict['account_record_qset'][0]
        try:
            balance = addr_bal(request.session.get('deposit_address')) - account_record.spent
            request.session['balance'] = str(balance)
        except:
            request.session['error_msg'] = error_msg + ' 1'
            return redirect('login')

        request.session['account_id'] = account_record.id
        request.session['account_url'] = account_record.url

        # Set cypher session
        if not account_record.verified_status:
            try:
                set_cypher_session(request, account_record.url)
            except:
                request.session['error_msg'] = error_msg + ' 2'
                return redirect('login')

        access.objects.create(account_id=account_record.id, ipaddress=get_client_ip(request), interface='web_ui').save()
        set_pass_token(request, u'dashboard')
        return redirect('dashboard')
    #endregion
    #region GET
    # Clear and set initial session data
    html_dtc = dict()
    html_dtc.update(dict(error_msg=request.session.get('error_msg')))
    html_dtc.update(dict(form=RegistrationForm()))
    html_dtc.update(csrf(request))

    request.session.flush()
    set_pass_token(request, u'login')
    return render_to_response('popsite/login.html', html_dtc)
    #endregion

def register(request):
    #region POST
    if request.POST:

        if not verify_pass_token(request, 'register'):
            return redirect('login')

        if not CaptchaTestForm(request.POST).is_valid():
            request.session['error_msg'] = 'You got the capture wrong'
            return redirect('login')

        account_record = account.objects.create()
        account_record.hashtwo = request.session.get('hashtwo')
        account_record.deposit_address = sha256(request.session.get('deposit_address')).hexdigest()
        account_record.save()
        request.session['account_id'] = account_record.id
        request.session['account_url'] = account_record.url

        try:
            balance = addr_bal(request.session.get('deposit_address'))
            request.session['balance'] = str(balance)
        except:
            request.session['error_msg'] = error_msg
            return redirect('login')

        access.objects.create(account_id=account_record.id, ipaddress=get_client_ip(request), interface='web_ui').save()
        set_pass_token(request, u'dashboard')
        return redirect('dashboard')
    #endregion
    #region GET
    if not verify_pass_token(request, 'register'):
        return redirect('login')

    price = get_bitcoin_price(request)
    if not price:
        return redirect('login')

    form = CaptchaTestForm()
    credit = Decimal('{0:.2f}'.format(0)) - Decimal('0.01')
    if credit < 0:
        credit = Decimal('{0:.2f}'.format(0))

    balance = 0
    html_dtc = dict(form=form,
                    deposit_address=request.session.get('deposit_address'),
                    price=price,
                    balance=Decimal("{0:.8f}".format(balance)),
                    credit=credit,
                    affordable_keys=free_keys)

    html_dtc.update(csrf(request))
    set_pass_token(request, u'register')
    return render_to_response('popsite/register.html', html_dtc)
    #endregion

def dashboard(request):
    #region POST
    if request.POST:
        if not verify_pass_token(request, 'dashboard'):
            return redirect('login')

        # Check if verify button clicked and redirect to verification page if so
        if request.POST.get('verify'):
            set_pass_token(request, u'verify')
            return redirect('verify')

        account_record = account.objects.filter(id=request.session.get('account_id'))[0]

        try:
            abs_balance = addr_bal(request.session.get('deposit_address'))
            balance = abs_balance - account_record.spent
            request.session['balance'] = str(balance)
        except:
            request.session['error_msg'] = error_msg
            return redirect('login')

        # Check for refund request
        if request.POST.get('refund_address'):

            # Check valid bitcoin address
            if not is_address_valid(request.POST['refund_address']):
                request.session['error_msg'] = 'Invalid bitcoin address'
                set_pass_token(request, u'dashboard')
                return redirect('dashboard')

            signed_tx = get_signed_tx(request, cryptoproof_payment_key_obj, account_record)
            if not signed_tx:
                request.session['error_msg'] = 'Invalid transaction'
                return redirect('login')

            try:
                pushtx(signed_tx.as_hex())
            except:
                request.session['error_msg'] = error_msg
                return redirect('login')

            payment_obj_lst = payment.objects.filter(account_id=account_record.id)
            if payment_obj_lst.exists():
                payment_obj_lst.delete()

            transaction.objects.create(account_id=account_record.id,
                                       btc_price=000,
                                       btc_amount=balance - Decimal(str(signed_tx.fee() / float(100000000)))).save()
                                       #btc_amount=balance - signed_tx.fee()).save()

            account_record.spent = 0
            request.session['balance'] = str(Decimal('{0:.8f}'.format(0)))
            account_record.save()

            request.session['error_msg'] = 'Withdrawal submitted successfully.'
            set_pass_token(request, u'dashboard')
            return redirect('dashboard')

        # Set variables
        submitted_url = request.POST.get('url').replace('www.', '')
        if not submitted_url:
            submitted_url = 'Anonymous'

        if request.POST.get('index_limit'):
            submitted_index_limit = int(request.POST.get('index_limit'))
        else:
            submitted_index_limit = account_record.index_limit

        price = get_bitcoin_price(request)
        if not price:
            return redirect('login')

        # Set maximum key index
        credit = Decimal('{0:.2f}'.format(price * balance)) - Decimal('0.01')
        if credit < 0:
            credit = Decimal('{0:.2f}'.format(0))

        affordable_keys = int(credit / cost_per_key)
        upper_index = affordable_keys + account_record.index_limit
        remaining_key_allowance = free_keys - account_record.index_limit
        if not remaining_key_allowance <= 0:
            upper_index += remaining_key_allowance

        if submitted_index_limit > upper_index:
            request.session['error_msg'] = 'Database conflict error'
            return redirect('login')

        # Reset verification status and cert_check to false if url has changed
        if not account_record.url == submitted_url:
            account_record.verified_status = False
            request.session['cert_check'] = False
            account_record.url = submitted_url
            request.session['account_url'] = submitted_url

        # Get cypher if verified status is false
        if not account_record.verified_status:
            try:
                set_cypher_session(request, submitted_url)
            except:
                request.session['error_msg'] = error_msg
                return redirect('login')

        # Check if account credited and update spend field if needed
        extra_keys = submitted_index_limit - account_record.index_limit
        if extra_keys < 1:
            account_record.save()
            set_pass_token(request, u'dashboard')
            return redirect('dashboard')

        # Does the person have any free keys left? How many?
        remaining_free_keys = 0
        if account_record.index_limit < free_keys:
            remaining_free_keys = free_keys - account_record.index_limit

        # Discount free keys
        chargable_keys = extra_keys - remaining_free_keys

        if not chargable_keys < 1:  # Charge
            btc_spent = Decimal("{0:.8f}".format((chargable_keys * cost_per_key) / price))
            account_record.spent += btc_spent

            transaction.objects.create(account_id=account_record.id,
                                       btc_price=price,
                                       btc_amount=btc_spent).save()

        # Create child objects
        create_keys.delay(request.session['xpubkeys'],
                          submitted_index_limit,
                          account_record.id,
                          account_record.index_limit,
                          request.session.get('sigs', '0'))

        account_record.index_limit = submitted_index_limit
        account_record.save()

        request.session['balance'] = str(abs_balance - account_record.spent)
        # Create and save transaction for spent funds
        if account_record.spent > network_transaction_fee:
            signed_tx = get_signed_tx(request, cryptoproof_payment_key_obj, account_record)
            if not signed_tx:
                request.session['error_msg'] = 'Invalid transaction'
                return redirect('login')

            payment_obj_lst = payment.objects.filter(account_id=account_record.id)
            if payment_obj_lst.exists():
                payment_obj_lst.delete()
            payment.objects.create(account_id=account_record.id, signed_tx=signed_tx.as_hex()).save()

        set_pass_token(request, u'dashboard')
        return redirect('dashboard')
    #endregion
    #region GET
    if not verify_pass_token(request, 'dashboard'):
        return redirect('login')

    # Get current bitcoin price
    price = get_bitcoin_price(request)
    if not price:
        return redirect('login')

    # Calculate max available keys based on excess balance
    account_record = account.objects.filter(id=request.session['account_id'])[0]
    balance = Decimal(request.session.get('balance'))

    # Blank url fiels if 'Anonymous'
    if account_record.url == 'Anonymous':
        account_record.url = ''

    # Set maximum key index
    credit = Decimal('{0:.2f}'.format(price * balance)) - Decimal('0.01')
    if credit < 0:
        credit = Decimal('{0:.2f}'.format(0))

    affordable_keys = int(credit / cost_per_key)
    upper_index = affordable_keys + account_record.index_limit
    remaining_key_allowance = free_keys - account_record.index_limit
    if not remaining_key_allowance <= 0:
        upper_index += remaining_key_allowance
    else:
        remaining_key_allowance = 0

    account_form = AccountsForm(instance=account_record)
    account_form.fields['index_limit'] = forms.IntegerField(label='Index Limit',
                                                            min_value=account_record.index_limit,
                                                            max_value=upper_index,
                                                            initial=account_record.index_limit)

    subkey_obj_qset = subkey.objects.filter(account_id=account_record.id, hits__gt=0)
    subkey_table = SubkeyTable(subkey_obj_qset, order_by="-last_accessed")
    subkey_table.paginate(per_page=10)

    transaction_obj_qset = transaction.objects.filter(account_id=account_record.id)
    transaction_table = TransactionTable(transaction_obj_qset, order_by="-id")
    transaction_table.paginate(per_page=10)

    login_obj_qset = access.objects.filter(account_id=account_record.id)
    login_table = LoginTable(login_obj_qset, order_by="-id")
    login_table.paginate(per_page=10)

    html_dtc = dict(index_limit=account_record.index_limit,
                    deposit_address=request.session.get('deposit_address'),
                    balance=balance,
                    credit=credit,
                    price=price,
                    affordable_keys=affordable_keys,
                    remaining_key_allowance=remaining_key_allowance,
                    login_table=login_table,
                    subkey_table=subkey_table,
                    subkey_table_exists=True if subkey_obj_qset.exists() else False,
                    transaction_table=transaction_table,
                    transaction_table_exists=True if transaction_obj_qset.exists() else False,
                    verified_status=account_record.verified_status,
                    logged_in=True,
                    account_form=account_form,
                    refund_form=False,
                    encrypted_str=request.session.get('encrypted_str'),
                    minimum_deposit=float(network_transaction_fee))

    # Include refund form if balance is high enough
    if balance > network_transaction_fee:
        refund_form = RefundForm()
        refund_form.fields['refund_address'] = forms.CharField(label='BTC Withdrawal Address\n')
        html_dtc.update(refund_form=refund_form)

    if request.session.get('error_msg'):
        html_dtc['error_msg'] = request.session['error_msg']
        del request.session['error_msg']

    if not account_record.verified_status:
        if request.session.get('encrypted_str'):
            html_dtc.update(encrypted_str=request.session.get('encrypted_str'))

    html_dtc.update(csrf(request))
    set_pass_token(request, u'dashboard')
    return render_to_response('popsite/dashboard.html', html_dtc, RequestContext(request))
    #endregion

def verify(request):
    #region POST
    if request.POST:

        if not verify_pass_token(request, 'verify'):
            return redirect('login')

        account_record = account.objects.filter(id=request.session['account_id'])[0]
        if not request.session['account_url'] == account_record.url:
            request.session['error_msg'] = 'Database conflict error'
            return redirect('login')

        set_pass_token(request, u'dashboard')
        if request.POST.get('back_button'):
            return redirect('dashboard')

        if request.POST.get('decoded_str', False) == request.session.get('decrypted_str', None):
            account_record = account.objects.filter(id=request.session['account_id'])[0]
            account_record.verified_status = True
            account_record.save()

            request.session['encrypted_str'] = False
            request.session['decrypted_str'] = False

        else:
            request.session['error_msg'] = 'Invalid decrypted string'

        return redirect('dashboard')
    #endregion
    #region GET
    if not verify_pass_token(request, 'verify'):
        return redirect('login')

    verification_form = VerificationForm()

    html_dtc = dict(verification_form=verification_form,
                    encrypted_str=request.session.get('encrypted_str'))

    if request.session.get('error_msg'):
        html_dtc.update(request.session.get('error_msg'))
        del request.session['error_msg']

    html_dtc.update(csrf(request))
    set_pass_token(request, u'verify')
    return render_to_response('popsite/verify.html', html_dtc)
    #endregion
