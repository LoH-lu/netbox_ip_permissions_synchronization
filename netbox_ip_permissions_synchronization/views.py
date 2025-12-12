## views.py
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
    # NetBox 3.5+ uses custom_field_data
    if hasattr(obj, "custom_field_data"):
        return obj.custom_field_data.get(field_name)

    # Older NetBox used obj.cf
    if hasattr(obj, "cf") and isinstance(obj.cf, dict):
        return obj.cf.get(field_name)

    # Legacy fallback: dict-like custom_fields
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
    
    # Try to use the relationship if available (faster)
    try:
        if hasattr(prefix, 'ip_addresses'):
            query_ips = prefix.ip_addresses.all()
            logger.info(f"Using prefix.ip_addresses relationship, found {query_ips.count()} IPs")
        else:
            # Fallback: filter by prefix family to reduce search space
            query_ips = IPAddress.objects.filter(
                address__family=prefix.prefix.version
            )
            logger.info(f"Filtering by family, checking {query_ips.count()} IP addresses against prefix {prefix.prefix}")
    except Exception as e:
        logger.warning(f"Could not optimize IP query: {e}, falling back to all IPs")
        query_ips = IPAddress.objects.all()
    
    for ip in query_ips:
        try:
            # Parse the IP address (remove CIDR if present)
            ip_str = str(ip.address).split('/')[0]
            ip_addr = ip_addr_obj(ip_str)
            
            if ip_addr in prefix_net:
                ip_tenant = ip.tenant
                
                # Get IP custom field values
                ip_permissions = get_custom_field_value(ip, "tenant_permissions")
                ip_permissions_ro = get_custom_field_value(ip, "tenant_permissions_ro")
                
                # Convert to display format
                ip_permissions_display = safe_to_string(ip_permissions)
                ip_permissions_ro_display = safe_to_string(ip_permissions_ro)
                
                ip_info = IPAddressInfo(
                    id=ip.id,
                    address=str(ip.address),
                    tenant_id=ip_tenant.id if ip_tenant else None,
                    tenant_name=ip_tenant.name if ip_tenant else "",
                    tenant_permissions=ip_permissions_display,
                    tenant_permissions_ro=ip_permissions_ro_display
                )
                ips_in_prefix.append(ip_info)
                logger.info(f"Found IP in prefix: {ip.address}")
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

        # Don't allow viewing container prefixes
        if prefix.status == 'container':
            messages.error(request, "Cannot synchronize permissions for container prefixes")
            return redirect('ipam:prefix_list')

        try:
            # Get prefix information
            prefix_tenant = prefix.tenant
            
            # Get custom field values
            prefix_permissions = get_custom_field_value(prefix, "tenant_permissions")
            prefix_permissions_ro = get_custom_field_value(prefix, "tenant_permissions_ro")
            
            # Convert to display format
            prefix_permissions_display = safe_to_string(prefix_permissions)
            prefix_permissions_ro_display = safe_to_string(prefix_permissions_ro)
            
            prefix_info = PrefixInfo(
                id=prefix.id,
                prefix=str(prefix.prefix),
                tenant_id=prefix_tenant.id if prefix_tenant else None,
                tenant_name=prefix_tenant.name if prefix_tenant else "",
                tenant_permissions=prefix_permissions_display,
                tenant_permissions_ro=prefix_permissions_ro_display
            )

            # Get IPs in prefix
            ips_in_prefix, _ = get_ips_in_prefix(prefix)
            logger.info(f"Total IPs in prefix: {len(ips_in_prefix)}")

            # Check which IPs need syncing
            ips_to_sync = []
            ips_synced = []

            for ip_info in ips_in_prefix:
                needs_sync = (
                    ip_info.tenant_permissions != prefix_info.tenant_permissions or
                    ip_info.tenant_permissions_ro != prefix_info.tenant_permissions_ro or
                    (ip_info.tenant_id != prefix_info.tenant_id)
                )

                if needs_sync:
                    ips_to_sync.append(ip_info)
                else:
                    ips_synced.append(ip_info)

            logger.info(f"IPs to sync: {len(ips_to_sync)}, IPs synced: {len(ips_synced)}")

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
            # Get prefix permissions and tenant
            prefix_tenant = prefix.tenant
            prefix_permissions = get_custom_field_value(prefix, "tenant_permissions")
            prefix_permissions_ro = get_custom_field_value(prefix, "tenant_permissions_ro")
    
            # Get all IPs in the prefix
            ips_in_prefix, prefix_net = get_ips_in_prefix(prefix)
    
            updated_count = 0
            failed_count = 0
    
            for ip_info in ips_in_prefix:
                try:
                    ip = IPAddress.objects.get(id=ip_info.id)
                    changed = False
    
                    # Sync tenant
                    if ip.tenant_id != (prefix_tenant.id if prefix_tenant else None):
                        ip.tenant = prefix_tenant
                        changed = True
    
                    # Sync custom fields
                    if getattr(ip, "custom_field_data", None) is not None:
                        if get_custom_field_value(ip, "tenant_permissions") != prefix_permissions:
                            ip.custom_field_data["tenant_permissions"] = prefix_permissions or []
                            changed = True
                        if get_custom_field_value(ip, "tenant_permissions_ro") != prefix_permissions_ro:
                            ip.custom_field_data["tenant_permissions_ro"] = prefix_permissions_ro or []
                            changed = True
                    else:
                        if getattr(ip, "cf", None) is not None:
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
    
            # Feedback messages
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
