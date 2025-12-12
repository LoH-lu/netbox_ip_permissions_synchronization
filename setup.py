import os
from setuptools import setup

_version_file = os.path.join(os.path.dirname(__file__), "netbox_ip_permissions_synchronization", "_version.py")
_version_data = {}
with open(_version_file, encoding="utf-8") as f:
    exec(f.read(), _version_data)

__version__ = _version_data["__version__"]
__author__ = _version_data["__author__"]
__author_email__ = _version_data["__author_email__"]
__description__ = _version_data["__description__"]
__license__ = _version_data["__license__"]

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="netbox_ip_permissions_synchronization",
    version=__version__,
    description=__description__,
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/LoH-lu/netbox_ip_permissions_synchronization/",
    author=__author__,
    author_email=__author_email__,
    license=__license__,
    packages=["netbox_ip_permissions_synchronization"],
    package_data={"netbox_ip_permissions_synchronization": ["templates/netbox_ip_permissions_synchronization/*.html"]},
    zip_safe=False,
)
