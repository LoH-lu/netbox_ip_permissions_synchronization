from netbox.plugins import PluginConfig
from ._version import __version__, __author__, __author_email__, __description__, __license__

class Config(PluginConfig):
    name = 'netbox_ip_permissions_synchronization'
    verbose_name = 'NetBox IP Permissions Synchronization'
    description = __description__
    version = __version__
    author = __author__
    author_email = __author_email__

config = Config
