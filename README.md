# netbox-ip-permissions-synchronization

## Overview

This plugin allows you to compare and synchronize IP address permissions (tenant assignments and custom permission fields) with their parent prefix in NetBox. It's useful for ensuring consistent permission and tenant assignments across all IP addresses within a prefix.

## Features

- Compare IP address permissions against their parent prefix
- View tenant and permission field assignments at a glance
- Synchronize all IP addresses with prefix permissions
- Automatic detection of mismatched permissions
- User-friendly interface with color-coded status indicators

## Compatibility

Tested with NetBox versions 4.3.7.

## Installation

If your NetBox 4 installation uses virtualenv, activate it like this:

```bash
source /opt/netbox/venv/bin/activate
```

Install the plugin from PyPI:

```bash
pip install netbox-ip-permissions-synchronization
```

Or clone this repository, then go to the folder with it and install the plugin:

```bash
pip install .
```

To enable the plugin, add the plugin's name to the `PLUGINS` list in `configuration.py` (it's usually located in `/opt/netbox/netbox/netbox/`) like so:

```python
PLUGINS = [
    'netbox_ip_permissions_synchronization'
]
```

Don't forget to restart NetBox:

```bash
sudo systemctl restart netbox
```

## Usage

Navigate to any Prefix in NetBox and look for the "Sync IP Permissions" button at the top of the page:

The synchronization page will show:
- Prefix information including tenant and permission assignments
- IP addresses that need synchronization (highlighted in yellow)
- IP addresses that are already synchronized (highlighted in green)

Select the IP addresses you want to synchronize using the checkboxes, then click either:
- **"Sync Selected IPs"** - Synchronize only the checked IP addresses
- **"Sync All IPs"** - Synchronize all IP addresses in the prefix

## Custom Fields Required

This plugin requires the following custom fields to be created in NetBox:

1. **tenant_permissions** - Text or object field to store read-write permission assignments
2. **tenant_permissions_ro** - Text or object field to store read-only permission assignments

These fields should be applied to both:
- IPAM > Prefix
- IPAM > IP Address

## How It Works

1. When you access the sync page for a prefix, the plugin fetches all IP addresses within that prefix
2. It compares each IP address's tenant and permission fields with the parent prefix
3. IP addresses with mismatched values are marked for synchronization
4. You can selectively sync individual IPs or all IPs at once
5. The sync operation updates:
   - Tenant assignment (if the prefix has a tenant set)
   - `tenant_permissions` custom field
   - `tenant_permissions_ro` custom field

## Plugin Settings

If you want to override the default values, configure the `PLUGINS_CONFIG` in your `configuration.py`:

```python
PLUGINS_CONFIG = {
    'netbox_ip_permissions_synchronization': {
        # Add any future configuration options here
    }
}
```

Currently, there are no required configuration options. All settings are managed through the NetBox UI.

## Permissions Required

To use this plugin, users need the following permissions:
- `ipam.view_ipaddress` - View IP addresses
- `ipam.change_ipaddress` - Modify IP addresses
- `ipam.view_prefix` - View prefixes

## Troubleshooting

### Custom fields not syncing
- Ensure that the `tenant_permissions` and `tenant_permissions_ro` custom fields exist in NetBox
- Verify that these custom fields are assigned to both Prefix and IP Address models
- Check that the field names match exactly (case-sensitive)

### No IP addresses found
- Make sure the prefix status is not "container" (container prefixes are skipped)
- Verify that IP addresses exist within the prefix range
- Check that you have permission to view the IP addresses

### Permission denied errors
- Ensure your user account has the required permissions listed above
- Contact your NetBox administrator if you lack necessary permissions

## Support

For issues, feature requests, or contributions, please visit the [project repository](https://github.com/loris-henrion/netbox-ip-permissions-synchronization).

## License

GNU General Public License v3.0 - See LICENSE file for details.