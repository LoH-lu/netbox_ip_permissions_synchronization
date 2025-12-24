import logging
from django.shortcuts import render, redirect
from django.views.generic import View
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.contrib import messages
from ipam.models import Prefix, IPAddress, VLAN
from ipaddress import ip_network, ip_address as ip_addr_obj

from .utils import IPAddressInfo, PrefixInfo, VLANInfo

logger = logging.getLogger(__name__)


def get_custom_field_value(obj, field_name):
    """Safely retrieve custom field from NetBox ORM object"""
    if hasattr(obj, "custom_field_data"):
        return obj.custom_field_data.get(field_name)
    if hasattr(obj, "cf") and isinstance(obj.cf, dict):
        return obj.cf.get(field_name)
    try:
        return obj.custom_fields.get(field_name)
    except Exception:
        pass
    return None


def set_custom_field_value(obj, field_name, value):
    """Safely set a custom field on a NetBox ORM object (supports both cf and custom_field_data)."""
    if hasattr(obj, "custom_field_data") and isinstance(obj.custom_field_data, dict):
        obj.custom_field_data[field_name] = value
        return True
    if hasattr(obj, "cf") and isinstance(obj.cf, dict):
        obj.cf[field_name] = value
        return True
    return False


def safe_to_string(value):
    """Safely convert value to string, handling None"""
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join([str(p.name) if hasattr(p, 'name') else str(p) for p in value])
    return str(value)


def get_ips_in_prefix(prefix):
    """Fetch all IP addresses within a prefix"""
    try:
        prefix_net = ip_network(prefix.prefix, strict=False)
    except ValueError as e:
        logger.error(f"Invalid prefix: {e}")
        raise ValueError(f"Invalid prefix format: {e}")

    ips_in_prefix = []

    try:
        if hasattr(prefix, 'ip_addresses'):
            query_ips = prefix.ip_addresses.all()
        else:
            query_ips = IPAddress.objects.filter(address__family=prefix.prefix.version)
    except Exception as e:
        logger.warning(f"Could not optimize IP query: {e}, falling back to all IPs")
        query_ips = IPAddress.objects.all()

    for ip in query_ips:
        try:
            ip_addr = ip_addr_obj(str(ip.address).split('/')[0])
            if ip_addr in prefix_net:
                ip_info = IPAddressInfo(
                    id=ip.id,
                    address=str(ip.address),
                    tenant_id=ip.tenant.id if ip.tenant else None,
                    tenant_name=ip.tenant.name if ip.tenant else "",
                    tenant_permissions=safe_to_string(get_custom_field_value(ip, "tenant_permissions")),
                    tenant_permissions_ro=safe_to_string(get_custom_field_value(ip, "tenant_permissions_ro"))
                )
                ips_in_prefix.append(ip_info)
        except (ValueError, AttributeError):
            continue

    return ips_in_prefix, prefix_net


class IPPermissionsSyncView(LoginRequiredMixin, PermissionRequiredMixin, View):
    """Synchronize IP address permissions from their parent prefix"""
    permission_required = (
        "ipam.view_ipaddress",
        "ipam.change_ipaddress",
        "ipam.view_prefix",
        "ipam.view_vlan",
        "ipam.change_vlan",
    )

    def get(self, request, prefix_id):
        try:
            prefix = Prefix.objects.get(id=prefix_id)
        except Prefix.DoesNotExist:
            messages.error(request, f"Prefix with ID {prefix_id} not found")
            return redirect('ipam:prefix_list')

        if prefix.status == 'container':
            messages.error(request, "Cannot synchronize permissions for container prefixes")
            return redirect('ipam:prefix_list')

        try:
            prefix_info = PrefixInfo(
                id=prefix.id,
                prefix=str(prefix.prefix),
                tenant_id=prefix.tenant.id if prefix.tenant else None,
                tenant_name=prefix.tenant.name if prefix.tenant else "",
                tenant_permissions=safe_to_string(get_custom_field_value(prefix, "tenant_permissions")),
                tenant_permissions_ro=safe_to_string(get_custom_field_value(prefix, "tenant_permissions_ro")),
            )

            vlan_info = None
            if getattr(prefix, "vlan", None):
                vlan = prefix.vlan
                vlan_info = VLANInfo(
                    id=vlan.id,
                    vid=getattr(vlan, "vid", None),
                    name=getattr(vlan, "name", "") or str(vlan),
                    tenant_id=vlan.tenant.id if getattr(vlan, "tenant", None) else None,
                    tenant_name=vlan.tenant.name if getattr(vlan, "tenant", None) else "",
                    tenant_permissions=safe_to_string(get_custom_field_value(vlan, "tenant_permissions")),
                    tenant_permissions_ro=safe_to_string(get_custom_field_value(vlan, "tenant_permissions_ro")),
                )

            ips_in_prefix, _ = get_ips_in_prefix(prefix)

            ips_to_sync = []
            ips_synced = []

            for ip_info in ips_in_prefix:
                if (
                    ip_info.tenant_permissions != prefix_info.tenant_permissions or
                    ip_info.tenant_permissions_ro != prefix_info.tenant_permissions_ro or
                    ip_info.tenant_id != prefix_info.tenant_id
                ):
                    ips_to_sync.append(ip_info)
                else:
                    ips_synced.append(ip_info)

            vlan_needs_sync = False
            if vlan_info is not None:
                vlan_needs_sync = not (
                    vlan_info.tenant_id == prefix_info.tenant_id
                    and vlan_info.tenant_permissions == prefix_info.tenant_permissions
                    and vlan_info.tenant_permissions_ro == prefix_info.tenant_permissions_ro
                )

            return render(
                request,
                "netbox_ip_permissions_synchronization/ip_permissions_sync.html",
                {
                    "prefix": prefix_info,
                    "vlan": vlan_info,
                    "vlan_needs_sync": vlan_needs_sync,
                    "ips_to_sync": ips_to_sync,
                    "ips_synced": ips_synced,
                    "ips_total": len(ips_in_prefix),
                }
            )
        except Exception as e:
            logger.error(f"Error in GET request: {str(e)}", exc_info=True)
            messages.error(request, f"An error occurred: {str(e)}")
            return redirect('ipam:prefix_list')

    def post(self, request, prefix_id):
        try:
            prefix = Prefix.objects.get(id=prefix_id)
        except Prefix.DoesNotExist:
            messages.error(request, "Prefix not found")
            return redirect('ipam:prefix_list')

        if prefix.status == 'container':
            messages.error(request, "Cannot synchronize permissions for container prefixes")
            return redirect('ipam:prefix_list')

        try:
            prefix_tenant = prefix.tenant
            prefix_permissions = get_custom_field_value(prefix, "tenant_permissions")
            prefix_permissions_ro = get_custom_field_value(prefix, "tenant_permissions_ro")

            # If the prefix has a VLAN assigned, sync the same tenant + permission fields to that VLAN as well.
            vlan_updated = False
            vlan_failed = False
            if getattr(prefix, "vlan", None):
                try:
                    vlan = VLAN.objects.get(id=prefix.vlan.id)
                    vlan_changed = False

                    if getattr(vlan, "tenant_id", None) != (prefix_tenant.id if prefix_tenant else None):
                        vlan.tenant = prefix_tenant
                        vlan_changed = True

                    if get_custom_field_value(vlan, "tenant_permissions") != prefix_permissions:
                        set_custom_field_value(vlan, "tenant_permissions", prefix_permissions or [])
                        vlan_changed = True
                    if get_custom_field_value(vlan, "tenant_permissions_ro") != prefix_permissions_ro:
                        set_custom_field_value(vlan, "tenant_permissions_ro", prefix_permissions_ro or [])
                        vlan_changed = True

                    if vlan_changed:
                        vlan.save()
                        vlan_updated = True
                except Exception:
                    vlan_failed = True
                    logger.error(
                        f"Error updating VLAN for prefix {prefix.id} (vlan={getattr(prefix.vlan, 'id', None)}):",
                        exc_info=True,
                    )

            ips_in_prefix, _ = get_ips_in_prefix(prefix)

            updated_count = 0
            failed_count = 0

            for ip_info in ips_in_prefix:
                try:
                    ip = IPAddress.objects.get(id=ip_info.id)
                    changed = False

                    if ip.tenant_id != (prefix_tenant.id if prefix_tenant else None):
                        ip.tenant = prefix_tenant
                        changed = True

                    if get_custom_field_value(ip, "tenant_permissions") != prefix_permissions:
                        set_custom_field_value(ip, "tenant_permissions", prefix_permissions or [])
                        changed = True
                    if get_custom_field_value(ip, "tenant_permissions_ro") != prefix_permissions_ro:
                        set_custom_field_value(ip, "tenant_permissions_ro", prefix_permissions_ro or [])
                        changed = True

                    if changed:
                        ip.save()
                        updated_count += 1

                except Exception as e:
                    failed_count += 1
                    logger.error(f"Error updating IP {ip_info.id}: {str(e)}", exc_info=True)

            message_parts = []
            if updated_count > 0:
                message_parts.append(f"synchronized {updated_count} IP address(es)")
            if vlan_updated:
                message_parts.append("synchronized VLAN permissions")
            if failed_count > 0:
                message_parts.append(f"failed to update {failed_count} IP address(es)")
            if vlan_failed:
                message_parts.append("failed to update VLAN")

            if message_parts:
                messages.success(request, f"Successfully {' and '.join(message_parts)}")
            else:
                messages.info(request, "No changes needed")

            return redirect(request.path)

        except Exception as e:
            logger.error(f"Error in POST request: {str(e)}", exc_info=True)
            messages.error(request, f"An error occurred: {str(e)}")
            return redirect(request.path)
