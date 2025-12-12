## template_content.py
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
            
            logger.info(f"Step 2: Object exists: {obj}")
            
            # Check status attribute
            logger.info(f"Step 3: Checking if object has 'status' attribute")
            if not hasattr(obj, 'status'):
                logger.warning("Step 3a: Object does not have 'status' attribute")
                return None
            
            logger.info(f"Step 3b: Object has 'status' attribute")
            logger.info(f"Step 3c: Status value type: {type(obj.status)}")
            logger.info(f"Step 3d: Status value: {obj.status}")
            
            status_value = None
            if obj.status is None:
                logger.info("Step 4: Status is None, allowing button to render")
            elif isinstance(obj.status, dict):
                logger.info(f"Step 4a: Status is dict: {obj.status}")
                status_value = obj.status.get('value')
                logger.info(f"Step 4b: Extracted status value: {status_value}")
            else:
                logger.info(f"Step 4c: Status is string or other type: {obj.status}")
                status_value = str(obj.status)
                logger.info(f"Step 4d: Converted status to string: {status_value}")
            
            # Check if it's a container
            logger.info(f"Step 5: Comparing status_value '{status_value}' with 'container'")
            if status_value == 'container':
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
            
        except AttributeError as ae:
            logger.error(f"AttributeError in PrefixViewExtension.buttons(): {str(ae)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None
        except TypeError as te:
            logger.error(f"TypeError in PrefixViewExtension.buttons(): {str(te)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error in PrefixViewExtension.buttons(): {str(e)}")
            logger.error(f"Error type: {type(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None

template_extensions = [PrefixViewExtension]
