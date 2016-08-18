import django_tables2 as tables
from models import transaction
from models import access
from models import subkey

class LoginTable(tables.Table):
    class Meta:
        model = access
        # add class="paleblue" to <table> tag
        attrs = {"class": "paleblue"}
        fields = ('id','ipaddress', 'interface')

class TransactionTable(tables.Table):
    class Meta:
        model = transaction
        # add class="paleblue" to <table> tag
        attrs = {"class": "paleblue"}
        fields = ('id','btc_price','btc_amount')

class SubkeyTable(tables.Table):
    class Meta:
        model = subkey
        # add class="paleblue" to <table> tag
        attrs = {"class": "paleblue"}
        fields = ('last_accessed','subkey_index','hits')