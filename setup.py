from setuptools import setup

with open('README.md', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='netbox_ip_permissions_synchronization',
    version='0.0.1',
    description='Syncing permissions on IP Addresses with those from their corresponding Prefix in NetBox',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Loris HENRION',
    author_email='loris_henrion@bce.lu',
    license='GPL-3.0',
    packages=["netbox_ip_permissions_synchronization"],
    package_data={"netbox_ip_permissions_synchronization": ["templates/netbox_ip_permissions_synchronization/*.html"]},
    zip_safe=False
)