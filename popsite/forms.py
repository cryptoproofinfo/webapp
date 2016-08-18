from django import forms
from captcha.fields import CaptchaField
from models import account

class SearchForm(forms.Form):
    info = forms.CharField(label='Bitcoin Address', max_length=35)  #, widget=forms.TextInput(attrs={'autocomplete': 'off'}))

class RegistrationForm(forms.Form):
    xpubkeys = forms.CharField(label='Extended Public Key(s)', max_length=1665, required=True)  #, widget=forms.TextInput(attrs={'autocomplete': 'off'}))
    sigs = forms.IntegerField(label='Signatories', min_value=0, max_value=15, initial=0, required=False)

class AccountsForm(forms.ModelForm):
    class Meta:
        model = account
        fields = ['url', 'index_limit']
    url = forms.URLField(label='Associated Url', required=False)
    index_limit = forms.IntegerField(label='Index Limit', min_value=0, max_value=1000000, initial=10, required=False)

class CaptchaTestForm(forms.Form):
    captcha = CaptchaField()

class VerificationForm(forms.Form):
    decoded_str = forms.CharField(label='Decoded String')

class RefundForm(forms.Form):
    refund_address = forms.CharField(label='BTC Withdrawal Address\n')
