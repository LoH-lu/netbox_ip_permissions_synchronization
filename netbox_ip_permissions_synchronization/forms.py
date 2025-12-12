## forms.py
from django import forms


class IPPermissionsSyncForm(forms.Form):
    sync_all = forms.BooleanField(required=False)
