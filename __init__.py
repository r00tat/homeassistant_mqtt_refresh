import homeassistant.loader as loader
import logging
from .jwt_token import Refresher

# The domain of your component. Should be equal to the name of your component.
DOMAIN = 'mqtt_refresh'

# List of integration names (string) your integration depends upon.
DEPENDENCIES = []

CONF_CONFIG_FILE = 'config_file'
DEFAULT_CONFIG_FILE = '/config/mqtt_password.yaml'

log = logging.getLogger(DOMAIN)


def setup(hass, config):
    """Set up the Hello MQTT component."""
    try:
        return setup_iot(hass, config)
    except:  # noqa
        log.exception("failed to initialize iot connection")
        return False


def setup_iot(hass, config):
    """ run iot setup """
    log.info("running setup of mqtt_refresh")
    domain_config = config[DOMAIN]
    Refresher(hass, **domain_config).start()

    # Return boolean to indicate that initialization was successfully.
    return True
