from netbox.plugins import PluginConfig


class Config(PluginConfig):
    name = 'netbox_ip_permissions_synchronization'
    verbose_name = 'NetBox IP Permissions Synchronization'
    description = 'Syncing permissions on IP Addresses with those from their corresponding Prefix in NetBox'
    version = '0.0.1'
    author = 'Loris HENRION'
    author_email = 'loris_henrion@bce.lu'
    base_url = 'ip-permissions'


config = Config