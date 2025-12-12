## template_content.py
import logging
from netbox.plugins import PluginTemplateExtension

logger = logging.getLogger(__name__)

class PrefixViewExtension(PluginTemplateExtension):
    models = ['ipam.prefix']
    
    def buttons(self):
        """Implements a sync IP permissions button at the top of the page"""
        try:
            obj = self.context.get('object')
            if not obj:
                logger.warning("No object in context for PrefixViewExtension")
                return None
            
            # Don't show button for container prefixes
            if hasattr(obj, 'status') and obj.status:
                # Status can be a dict with 'value' key or a string
                status_value = obj.status.get('value') if isinstance(obj.status, dict) else obj.status
                if status_value == 'container':
                    logger.info(f"Skipping button for container prefix: {obj}")
                    return None
            
            logger.info(f"Rendering button for prefix: {obj}")
            return self.render(
                "netbox_ip_permissions_synchronization/sync_ip_permissions_button.html",
                extra_context={
                    "prefix": obj
                }
            )
        except AttributeError as e:
            logger.warning(f"AttributeError in PrefixViewExtension.buttons(): {str(e)}")
            return None
        except TypeError as e:
            logger.warning(f"TypeError in PrefixViewExtension.buttons(): {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error in PrefixViewExtension.buttons(): {str(e)}", exc_info=True)
            return None

template_extensions = [PrefixViewExtension]
