from setuptools import setup
import sys
import os

# Add root directory to path to import _version
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from _version import __version__, __author__, __author_email__, __description__, __license__

with open('README.md', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='netbox_ip_permissions_synchronization',
    version=__version__,
    description=__description__,
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/LoH-lu/netbox_ip_permissions_synchronization/',
    author=__author__,
    author_email=__author_email__,
    license=__license__,
    packages=["netbox_ip_permissions_synchronization"],
    package_data={"netbox_ip_permissions_synchronization": ["templates/netbox_ip_permissions_synchronization/*.html"]},
    zip_safe=False
)
