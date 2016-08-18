from django.db import models

# Create your models here.
class account(models.Model):
    url = models.URLField(max_length=200, blank=True)
    index_limit = models.IntegerField(default=0)
    verified_status = models.BooleanField(blank=False, null=False, default=False, editable=False)
    deposit_address = models.CharField(max_length=64)
    spent = models.DecimalField(max_digits=8, decimal_places=8, default=0, editable=False)
    hashtwo = models.CharField(max_length=64, editable=False)

class subkey(models.Model):
    account_id = models.IntegerField()
    subkey_index = models.IntegerField(verbose_name='Subkey Index:', blank=True, null=True)
    hash = models.CharField(max_length=64)
    hits = models.IntegerField(verbose_name='Hits:', blank=True, null=True)
    last_accessed = models.DateTimeField(verbose_name="Last Accessed", null=True)

class transaction(models.Model):
    id = models.DateTimeField(verbose_name='Date:', primary_key=True, auto_now=True, editable=False)
    account_id = models.IntegerField()
    btc_price = models.DecimalField(verbose_name='BTC Price:', max_digits=7, decimal_places=2)
    btc_amount = models.DecimalField(verbose_name='BTC Amount:', max_digits=8, decimal_places=8, default=0, editable=False)

class access(models.Model):
    id = models.DateTimeField(verbose_name='Date',primary_key=True,auto_now=True, editable=False)
    account_id = models.IntegerField(editable=False)
    ipaddress = models.GenericIPAddressField(verbose_name='IP Address:', null=True, blank=True)
    interface = models.CharField(verbose_name='Interface', max_length=23, null=False, blank=False)

class payment(models.Model):
    id = models.DateTimeField(verbose_name='Date',primary_key=True,auto_now=True, editable=False)
    account_id = models.IntegerField(editable=False)
    signed_tx = models.TextField()
