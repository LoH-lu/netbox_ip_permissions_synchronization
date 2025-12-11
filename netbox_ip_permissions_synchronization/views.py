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


class IPPermissionsSyncView(LoginRequiredMixin, PermissionRequiredMixin, View):
    """Synchronize IP address permissions from their parent prefix"""
    permission_required = ("ipam.view_ipaddress", "ipam.change_ipaddress", "ipam.view_prefix")

    def get(self, request, prefix_id):
        try:
            prefix = Prefix.objects.get(id=prefix_id)
        except Prefix.DoesNotExist:
            messages.error(request, f"Prefix with ID {prefix_id} not found")
            return redirect('ipam:prefix_list')

        try:
            # Get prefix information
            prefix_tenant = prefix.tenant
            
            # Get custom field values
            prefix_permissions = get_custom_field_value(prefix, "tenant_permissions")
            prefix_permissions_ro = get_custom_field_value(prefix, "tenant_permissions_ro")
            
            # Convert to display format
            prefix_permissions_display = ""
            if prefix_permissions:
                if isinstance(prefix_permissions, list):
                    prefix_permissions_display = ", ".join([str(p.name) if hasattr(p, 'name') else str(p) for p in prefix_permissions])
                else:
                    prefix_permissions_display = str(prefix_permissions)
            
            prefix_permissions_ro_display = ""
            if prefix_permissions_ro:
                if isinstance(prefix_permissions_ro, list):
                    prefix_permissions_ro_display = ", ".join([str(p.name) if hasattr(p, 'name') else str(p) for p in prefix_permissions_ro])
                else:
                    prefix_permissions_ro_display = str(prefix_permissions_ro)
            
            prefix_info = PrefixInfo(
                id=prefix.id,
                prefix=str(prefix.prefix),
                tenant_id=prefix_tenant.id if prefix_tenant else None,
                tenant_name=prefix_tenant.name if prefix_tenant else "",
                tenant_permissions=prefix_permissions_display,
                tenant_permissions_ro=prefix_permissions_ro_display
            )

            # Get all IP addresses and filter by prefix network
            try:
                prefix_net = ip_network(prefix.prefix, strict=False)
            except ValueError as e:
                logger.error(f"Invalid prefix: {e}")
                messages.error(request, f"Invalid prefix format: {e}")
                return redirect('ipam:prefix_list')
            
            ips_in_prefix = []
            all_ips = IPAddress.objects.all()
            
            logger.info(f"Checking {all_ips.count()} IP addresses against prefix {prefix.prefix}")
            
            for ip in all_ips:
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
                        ip_permissions_display = ""
                        if ip_permissions:
                            if isinstance(ip_permissions, list):
                                ip_permissions_display = ", ".join([str(p.name) if hasattr(p, 'name') else str(p) for p in ip_permissions])
                            else:
                                ip_permissions_display = str(ip_permissions)
                        
                        ip_permissions_ro_display = ""
                        if ip_permissions_ro:
                            if isinstance(ip_permissions_ro, list):
                                ip_permissions_ro_display = ", ".join([str(p.name) if hasattr(p, 'name') else str(p) for p in ip_permissions_ro])
                            else:
                                ip_permissions_ro_display = str(ip_permissions_ro)
                        
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

            logger.info(f"Total IPs in prefix: {len(ips_in_prefix)}")

            # Check which IPs need syncing
            ips_to_sync = []
            ips_synced = []

            for ip_info in ips_in_prefix:
                needs_sync = (
                    ip_info.tenant_permissions != prefix_info.tenant_permissions or
                    ip_info.tenant_permissions_ro != prefix_info.tenant_permissions_ro or
                    (prefix_info.tenant_id and ip_info.tenant_id != prefix_info.tenant_id)
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

        try:
            sync_all = request.POST.get('sync_all') == 'true'
            selected_ip_ids = request.POST.getlist('selected_ips')
            selected_ip_ids = [int(ip_id) for ip_id in selected_ip_ids if ip_id.isdigit()]

            # Get prefix permissions and tenant
            prefix_tenant = prefix.tenant
            prefix_permissions = get_custom_field_value(prefix, "tenant_permissions")
            prefix_permissions_ro = get_custom_field_value(prefix, "tenant_permissions_ro")

            # Get IPs to update
            try:
                prefix_net = ip_network(prefix.prefix, strict=False)
            except ValueError as e:
                messages.error(request, f"Invalid prefix format: {e}")
                return redirect(request.path)

            if sync_all:
                ips_query = IPAddress.objects.all()
            else:
                ips_query = IPAddress.objects.filter(id__in=selected_ip_ids)

            ips_to_update = []
            for ip in ips_query:
                try:
                    ip_str = str(ip.address).split('/')[0]
                    ip_addr = ip_addr_obj(ip_str)
                    if ip_addr in prefix_net:
                        ips_to_update.append(ip)
                except (ValueError, AttributeError):
                    continue

            # Update IPs
            updated_count = 0
            failed_count = 0
            
            for ip in ips_to_update:
                try:
                    # Get current values using our helper function
                    current_perms = get_custom_field_value(ip, 'tenant_permissions')
                    current_perms_ro = get_custom_field_value(ip, 'tenant_permissions_ro')
                    
                    changed = False
                    
                    # Update tenant if prefix has one and it differs
                    if prefix_tenant and ip.tenant_id != prefix_tenant.id:
                        ip.tenant = prefix_tenant
                        changed = True
                    
                    # Update custom fields using bracket notation
                    try:
                        if prefix_permissions is not None and current_perms != prefix_permissions:
                            if hasattr(ip, "custom_field_data"):
                                ip.custom_field_data["tenant_permissions"] = prefix_permissions
                            else:
                                # fallback for old NetBox versions
                                ip.cf["tenant_permissions"] = prefix_permissions
                            changed = True
                            logger.info(f"Setting tenant_permissions to {prefix_permissions}")
                    except Exception as e:
                        logger.warning(f"Could not set tenant_permissions: {e}")
                    
                    try:
                        if prefix_permissions_ro is not None and current_perms_ro != prefix_permissions_ro:
                            if hasattr(ip, "custom_field_data"):
                                ip.custom_field_data["tenant_permissions_ro"] = prefix_permissions_ro
                            else:
                                ip.cf["tenant_permissions_ro"] = prefix_permissions_ro
                            changed = True
                            logger.info(f"Setting tenant_permissions_ro to {prefix_permissions_ro}")
                    except Exception as e:
                        logger.warning(f"Could not set tenant_permissions_ro: {e}")
                    
                    # Save if anything changed
                    if changed:
                        ip.save()
                        updated_count += 1
                        logger.info(f"Successfully updated IP {ip.id}")
                    else:
                        logger.info(f"IP {ip.id} already synchronized")
                    
                except Exception as e:
                    failed_count += 1
                    logger.error(f"Error updating IP {ip.id}: {str(e)}", exc_info=True)

            # Generate result messages
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