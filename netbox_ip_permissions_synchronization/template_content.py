# template_content.py
import logging
import traceback
from netbox.plugins import PluginTemplateExtension

logger = logging.getLogger(__name__)

class PrefixViewExtension(PluginTemplateExtension):
    models = ['ipam.prefix']

    def buttons(self):
        """Implements a sync IP permissions button at the top of the page"""
        try:
            obj = self.context.get('object')
            if not obj:
                return ""

            # Directly get the status value
            raw_status_value = obj.status
            logger.info(f"Status value: {raw_status_value}")

            # Skip rendering if the status is 'container'
            if raw_status_value == 'container':
                logger.info("Status is 'container', skipping button render")
                return ""

            logger.info("Status is not 'container', proceeding with button render")

            # Render the button template
            result = self.render(
                "netbox_ip_permissions_synchronization/sync_ip_permissions_button.html",
                extra_context={
                    "prefix": obj
                }
            )
            return result

        except Exception as e:
            logger.error(f"Unexpected error in PrefixViewExtension.buttons(): {type(e).__name__}: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return ""

template_extensions = [PrefixViewExtension]
