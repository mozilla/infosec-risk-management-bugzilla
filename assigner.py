import bugzilla
from datetime import datetime, timedelta
import requests
import sys
import yaml
import os
import random
from dotdict import DotDict
# from awsparameterstoreprovider import AWSParameterstoreProvider


class Assigner:
    def __init__(self, url, service_cfg, dry_run=True):
        self.service = service_cfg
        self.assignees = self.service["assignees"]
        self.api_key = "CHANGE THIS TO PARAM STORE CALL"
        self.api = bugzilla.Bugzilla(url=url, api_key=self.api_key)
        self.dry_run = dry_run

    def next_assignee(self):
        return random.choice(self.assignees)

    def get_terms(self):
        # Do we have any bugs in the queue?
        return [{'product': self.service['product']}, {'component': self.service['component']},
                {'status': 'NEW'}, {'status': 'UNCONFIRMED'}
                ]

    def assign(self):
        assignee = next_assignee()
        terms = get_terms()

        try:
            bugs = self.api.search_bugs(terms)['bugs']
        except Exception as e:
            logger.warning(
                'Bugzilla search query failed, cannot auto-assign bugs: {}'.format(e))
            sys.exit(127)

        try:
            bugzilla.DotDict(bugs[-1])
            logger.debug(
                "Found {} unassigned bug(s). Assigning work!".format(len(bugs)))
            for bug in bugs:
                # Is this a valid request bug?
                if bug.get('whiteboard').startswith('autoentry'):
                    logger.debug(
                        "{} is not valid, skipping".format(bug.get('id')))
                    continue

                bug_up = bugzilla.DotDict()
                bug_up.assigned_to = assignee
                bug_up.status = 'ASSIGNED'
                try:
                    if not self.dry_run:
                        logger.info("Updating bug {} assigning {}".format(
                            bug.get('id'), assignee))
                        api.put_bug(bug.get('id'), bug_up)
                    else:
                        logger.info("Dry run, action not performed: would update bug {} assigning {}".format(bug.get('id'),
                                                                                                             assignee))
                except Exception as e:
                    logging.debug(
                        "Failed to update bug {}: {}".format(bug.get('id'), e))

        except IndexError:
            logger.info("No unassigned bugs for component")
