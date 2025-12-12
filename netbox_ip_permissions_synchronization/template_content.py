# template_content.py (Revised)
import logging
import traceback
from netbox.plugins import PluginTemplateExtension

logger = logging.getLogger(__name__)

class PrefixViewExtension(PluginTemplateExtension):
    models = ['ipam.prefix']
    
    def buttons(self):
        """Implements a sync IP permissions button at the top of the page"""
        try:
            logger.info("=== PrefixViewExtension.buttons() called ===")
            
            obj = self.context.get('object')
            logger.info(f"Step 1: Got object from context: {obj}")
            
            if not obj:
                logger.warning("Step 2: No object in context for PrefixViewExtension")
                return None
            
            # ... Steps 2 and 3 omitted for brevity, they are fine ...
            
            status_value = None
            if obj.status is None:
                logger.info("Step 4: Status is None, allowing button to render")
            elif isinstance(obj.status, dict):
                logger.info(f"Step 4a: Status is dict: {obj.status}")
                # Use .get() which returns None if 'value' is missing
                status_value = obj.status.get('value') 
                logger.info(f"Step 4b: Extracted status value: {status_value}")
            else:
                logger.info(f"Step 4c: Status is string or other type: {obj.status}")
                status_value = obj.status
                logger.info(f"Step 4d: Used status value: {status_value}")
            
            # --- THE CRITICAL FIX: Ensure status_value is a string for logging/comparison ---
            # Convert status_value to a string if it exists, otherwise use an empty string.
            safe_status_value = str(status_value) if status_value is not None else ""
            
            logger.info(f"Step 5: Comparing safe_status_value '{safe_status_value}' with 'container'")
            
            # Check if it's a container
            if safe_status_value == 'container':
                logger.info(f"Step 5a: Status is 'container', skipping button render")
                return None
            
            logger.info(f"Step 5b: Status is not 'container', proceeding with button render")
            
            logger.info("Step 6: Rendering button template")
            result = self.render(
                "netbox_ip_permissions_synchronization/sync_ip_permissions_button.html",
                extra_context={
                    "prefix": obj
                }
            )
            logger.info(f"Step 6a: Button rendered successfully")
            return result
            
        except Exception as e:
            logger.error(f"Error in PrefixViewExtension.buttons(): {str(e)}")
            logger.error(f"Error type: {type(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None

template_extensions = [PrefixViewExtension]
