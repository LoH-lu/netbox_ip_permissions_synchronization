from django import forms


class IPPermissionsSyncForm(forms.Form):
    sync_all = forms.BooleanField(required=False)
    selected_ips = forms.CharField(required=False, widget=forms.HiddenInput())