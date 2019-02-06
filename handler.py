import datetime
import logging

from config import Config
from casa import Casa
from dotdict import DotDict

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def run(event, context):
    config = Config("config.yml")
    dry_run = True
    bmo_url = config.bmo_url()
    va_service = config.service('va')
    rra_service = config.service('rra')

    Assigner(bmo_url, va_service, dry_run).assign()
    Assigner(bmo_url, rra_service, dry_run).assign()

    # TODO: do casa bits
