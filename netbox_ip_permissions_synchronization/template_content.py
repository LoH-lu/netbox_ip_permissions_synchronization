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
            
            logger.info(f"Rendering button for prefix: {obj}")
            return self.render(
                "netbox_ip_permissions_synchronization/sync_ip_permissions_button.html",
                extra_context={
                    "prefix": obj
                }
            )
        except Exception as e:
            logger.error(f"Error in PrefixViewExtension.buttons(): {str(e)}", exc_info=True)
            return None


template_extensions = [PrefixViewExtension]