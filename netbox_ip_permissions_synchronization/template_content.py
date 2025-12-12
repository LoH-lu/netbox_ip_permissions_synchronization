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
            if not obj or not hasattr(obj, 'status'):
                return None

            # 1. Determine the raw status value
            raw_status_value = None
            if obj.status is None:
                logger.info("Step 4: Status is None.")
            elif isinstance(obj.status, dict):
                raw_status_value = obj.status.get('value')
                logger.info(f"Step 4a: Extracted raw status value from dict: {raw_status_value}")
            else:
                raw_status_value = obj.status
                logger.info(f"Step 4c: Used raw status value: {raw_status_value}")

            # 2. Ensure the value used for logging/comparison is a safe string
            safe_status_value = str(raw_status_value) if raw_status_value is not None else ""
            logger.info(f"Step 5: Comparing safe_status_value '{safe_status_value}' with 'container'")

            # 3. Skip rendering if it's a container
            if safe_status_value == 'container':
                logger.info("Step 5a: Status is 'container', skipping button render")
                return None

            logger.info("Step 5b: Status is not 'container', proceeding with button render")

            # 4. Defensive sanitization: ensure no None values in custom_fields
            if hasattr(obj, 'custom_fields') and obj.custom_fields:
                for key, val in obj.custom_fields.items():
                    if val is None:
                        obj.custom_fields[key] = ""

            # 5. Render the button template safely
            logger.info("Step 6: Rendering button template")
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
            return None

template_extensions = [PrefixViewExtension]
