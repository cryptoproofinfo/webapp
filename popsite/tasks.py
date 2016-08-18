from popsite.models import subkey, account
from pycoin.key.Key import Key
from pycoin.tx.pay_to import ScriptMultisig, address_for_pay_to_script
from celery.decorators import task
from hashlib import sha256

split_string = 'xpub661MyMwAqRbc'

def get_multisig_address(keys, sigs=0, finish=0, start=0):
    if finish == 0:
        redeem_script = ScriptMultisig(n=sigs, sec_keys=[key.sec() for key in keys]).script()
        yield address_for_pay_to_script(redeem_script)
    else:
        while start < finish:
            redeem_script = ScriptMultisig(n=sigs, sec_keys=[key.subkey(start).sec() for key in keys]).script()
            start += 1
            yield address_for_pay_to_script(redeem_script)

@task(name='popsite.tasks.create_keys')
def create_keys(xpubkey_txt, submitted_index_limit, ac_rec_id, ac_rec_index_limit, sigs):

    xpubkey_str_lst = []
    for i in xpubkey_txt.split(split_string):
        xpubkey_str_lst.append(split_string + i)
    del xpubkey_str_lst[0]

    xpubkey_obj_lst = []
    for i in xpubkey_str_lst:
        xpubkey_obj_lst.append(Key.from_text(i))

    # Create child objects
    c = ac_rec_index_limit if submitted_index_limit != ac_rec_index_limit else 0
    if len(xpubkey_obj_lst) == 1:
        child_keys = xpubkey_obj_lst[0].children(max_level=(submitted_index_limit - c) - 1, start_index=c, include_hardened=False)
        #   Create hash key table
        for i in child_keys:
            subkey.objects.create(account_id=ac_rec_id, subkey_index=c, hash=sha256(i.address().encode('utf8')).hexdigest(), hits=0, last_accessed=None).save()
            c += 1

    else:
        child_keys = get_multisig_address(xpubkey_obj_lst, int(sigs), submitted_index_limit, c)
        #   Create hash key table
        for i in child_keys:
            subkey.objects.create(account_id=ac_rec_id, subkey_index=c, hash=sha256(i.encode('utf8')).hexdigest(), hits=0, last_accessed=None).save()
            c += 1
