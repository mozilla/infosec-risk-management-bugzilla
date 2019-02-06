import logging
import sys
import yaml


class Config(object):
    """Support loading config parameters."""

    def __init__(self, config_path, logger=logging.getLogger(__name__)):
        self.config_path = config_path
        self.config = {}
        try:
            with open(self.config_path) as fd:
                self.config = yaml.load(fd)
        except Exception as e:
            logger.critical("Could not parse configuration file: {}".format(e))
            sys.exit(127)

    def service(self, service_name):
        return self.config['bugzilla'][service_name]

    def bmo_url(self):
        return self.config['bugzilla']['url']
