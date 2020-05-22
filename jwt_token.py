""" jwt token lib """
# [START iot_mqtt_includes]
from datetime import datetime, timedelta
import yaml
import json
import jwt
import threading
import time
import logging

REQUIREMENTS = ["pyjwt==1.7.1", "pyyaml"]
log = logging.getLogger("mqtt_refresh")

MIN_REFRESH = 60

# [END iot_mqtt_includes]


# [START iot_mqtt_jwt]
def create_jwt(project_id, private_key_file, algorithm, lifetime=60 * 20):
    """Creates a JWT (https://jwt.io) to establish an MQTT connection.
        Args:
         project_id: The cloud project ID this device belongs to
         private_key_file: A path to a file containing either an RSA256 or
                 ES256 private key.
         algorithm: The encryption algorithm to use. Either 'RS256' or 'ES256'
        Returns:
            A JWT generated from the given project_id and private key, which
            expires in 20 minutes. After 20 minutes, your client will be
            disconnected, and a new JWT will have to be generated.
        Raises:
            ValueError: If the private_key_file does not contain a known key.
        """

    token = {
        # The time that the token was issued at
        'iat': datetime.utcnow(),
        # The time the token expires.
        'exp': datetime.utcnow() + timedelta(seconds=lifetime),
        # The audience field should always be set to the GCP project id.
        'aud': project_id
    }

    # Read the private key file.
    with open(private_key_file, 'r') as f:
        private_key = f.read()

    print('Creating JWT using {} from private key file {}'.format(algorithm, private_key_file))

    return jwt.encode(token, private_key, algorithm=algorithm)


# [END iot_mqtt_jwt]


class Refresher(threading.Thread):
    """ refresh credentials and reload homeassistant """

    def __init__(self,
                 hass,
                 project_id,
                 private_key_file,
                 config_file="/config/mqtt_password.yaml",
                 algorithm="RS256",
                 jwt_lifetime=60 * 60 * 12,
                 early_timer=5 * 60,
                 *args,
                 **kwargs):
        super(Refresher, self).__init__(*args, **kwargs)
        self.hass = hass
        self.project_id = project_id
        self.private_key_file = private_key_file
        self.config_file = config_file
        self.algorithm = algorithm
        self.is_running = True
        self.jwt_lifetime = jwt_lifetime  # 12 hours
        self.early_timer = early_timer  # 5 minutes

    def run(self):
        """ refresh creds """
        while self.is_running:
            reschedule_in = self.create_and_refresh()
            log.info("reschedulin in %s seconds", reschedule_in)
            time.sleep(reschedule_in)

    def create_and_refresh(self):
        try:
            expires = self.get_expires()
            now = datetime.utcnow()
            if expires < now or (expires - now).total_seconds() < self.early_timer:
                log.info("refreshing JWT token, token expiry date: %s", expires.isoformat())
                self.create_key()
                self.refresh_homeassistant()
                expires = self.get_expires()
            next_refresh_in = (expires - now).total_seconds() - self.early_timer
            if next_refresh_in < MIN_REFRESH:
                return MIN_REFRESH
            return next_refresh_in
        except:
            log.exception("failed to refresh jwt token")
            # try again in a minute
            return MIN_REFRESH

    def get_expires(self):
        """ fetch jwt token and parse expire time """
        try:
            with open(self.config_file, 'r') as config_file:
                token = yaml.safe_load(config_file)
            payload = jwt.decode(token, verify=False)
            expiration = datetime.utcfromtimestamp(payload.get('exp'))
            log.info("JWT token expires on %s", expiration.isoformat())
            return expiration
        except:
            log.exception("failed to parse JWT token")
            return datetime.utcnow()

    def create_key(self):
        """ create a new key and write to file """
        log.info("creating new %s JWT token for project %s with key %s", self.algorithm,
                 self.project_id, self.private_key_file)
        token = create_jwt(self.project_id, self.private_key_file, self.algorithm,
                           self.jwt_lifetime)
        with open(self.config_file, 'w') as config_file:
            log.info("writing JWT token to %s", self.config_file)
            config_file.write(json.dumps(token.decode('utf-8')))

    def refresh_homeassistant(self):
        """ refresh homeassistant config """
        # self.hass.restart()
        # reload
        # log.info("reloading homeassistant config")
        # self.hass.services.call("homeassistant", "reload_core_config")
        # restart
        log.info("restarting homeassistant because of mqtt password change")
        self.hass.services.call("homeassistant", "restart")
