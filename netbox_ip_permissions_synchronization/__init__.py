from netbox.plugins import PluginConfig
import os

_version_file = os.path.join(os.path.dirname(__file__), '..', '_version.py')
_version_data = {}
with open(_version_file, encoding="utf-8") as f:
    exec(f.read(), _version_data)

__version__ = _version_data["__version__"]
__author__ = _version_data["__author__"]
__author_email__ = _version_data["__author_email__"]
__description__ = _version_data["__description__"]
__license__ = _version_data["__license__"]


class Config(PluginConfig):
    name = 'netbox_ip_permissions_synchronization'
    verbose_name = 'NetBox IP Permissions Synchronization'
    description = __description__
    version = __version__
    author = __author__
    author_email = __author_email__


config = Config
