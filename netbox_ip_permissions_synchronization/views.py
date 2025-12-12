import logging
from django.shortcuts import render, redirect
from django.views.generic import View
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.contrib import messages
from ipam.models import Prefix, IPAddress
from ipaddress import ip_network, ip_address as ip_addr_obj

from .utils import IPAddressInfo, PrefixInfo

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
    permission_required = ("ipam.view_ipaddress", "ipam.change_ipaddress", "ipam.view_prefix")

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

            return render(
                request,
                "netbox_ip_permissions_synchronization/ip_permissions_sync.html",
                {
                    "prefix": prefix_info,
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

                    if hasattr(ip, "custom_field_data"):
                        if get_custom_field_value(ip, "tenant_permissions") != prefix_permissions:
                            ip.custom_field_data["tenant_permissions"] = prefix_permissions or []
                            changed = True
                        if get_custom_field_value(ip, "tenant_permissions_ro") != prefix_permissions_ro:
                            ip.custom_field_data["tenant_permissions_ro"] = prefix_permissions_ro or []
                            changed = True
                    elif hasattr(ip, "cf"):
                        if get_custom_field_value(ip, "tenant_permissions") != prefix_permissions:
                            ip.cf["tenant_permissions"] = prefix_permissions or []
                            changed = True
                        if get_custom_field_value(ip, "tenant_permissions_ro") != prefix_permissions_ro:
                            ip.cf["tenant_permissions_ro"] = prefix_permissions_ro or []
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
            if failed_count > 0:
                message_parts.append(f"failed to update {failed_count} IP address(es)")

            if message_parts:
                messages.success(request, f"Successfully {' and '.join(message_parts)}")
            else:
                messages.info(request, "No changes needed")

            return redirect(request.path)

        except Exception as e:
            logger.error(f"Error in POST request: {str(e)}", exc_info=True)
            messages.error(request, f"An error occurred: {str(e)}")
            return redirect(request.path)
