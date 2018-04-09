#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Copyright (c) 2016-2018 Mozilla Corporation

import argparse
import bugzilla
import logging
import pickle
import requests
import sys
import yaml
import os

def main():
    global logger

    # Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug mode')
    parser.add_argument('--dry-run', action="store_true", help='Perform all read operations, and no write operations. This means no bug '
            'will be updated, CASA won\'t be updated, etc.')
    parser.add_argument('--configfile', help='Config file that specifies all the parameters we need to assign bugs')

    args = parser.parse_args()

    # Logging
    logger = logging.getLogger(__name__)
    formatstr="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
    logging.basicConfig(format=formatstr, datefmt="%H:%M:%S", stream=sys.stderr)
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # Do things!
    try:
        with open(args.configfile) as fd:
            config = yaml.load(fd)
    except Exception as e:
        logger.critical("Could not parse configuration file: {}".format(e))
        sys.exit(127)
    bcfg = config.get('bugzilla')
    bapi = bugzilla.Bugzilla(url=bcfg.get('url'), api_key=os.environ.get('BUGZILLA_API_KEY'))

    autoassign(bapi, bcfg.get('rra'), args.dry_run)
    autoassign(bapi, bcfg.get('va'), args.dry_run)


def autoassign(bapi, cfg, dry_run):
    """
    This will search through unassigned bugs and assign them automatically.
    @bcfg: bugzilla configuration dict
    """
    global logger

    reset_assignees = False # Controls if we're going to rewrite the cache that record who's the next assignee or not
    try:
        with open(cfg.get('cache'), 'rb') as f:
            (assign_list, assign_hash) = pickle.load(f)
            if set(assign_list) != set(assign_hash):
                logger.info("List of assignees changed, resetting list!")
                reset_assignees = True
    except FileNotFoundError:
        reset_assignees = True

    if reset_assignees:
        assign_hash = cfg.get('assignees')
        assign_list = assign_hash[:]
        logger.info("Configuring defaults for the NEW assignment list: {}".format(assign_hash))

    # Do we have any bugs in the queue?
    terms = [{'product': cfg.get('product')}, {'component': cfg.get('component')},
            {'status': 'NEW'}, {'status': 'UNCONFIRMED'}
            ]

    bugs = bapi.search_bugs(terms)['bugs']

    try:
        bugzilla.DotDict(bugs[-1])
        logger.debug("Found {} unassigned bug(s). Assigning work!".format(len(bugs)))
        for bug in bugs:
            # Is this a valid request bug?
            if bug.get('whiteboard').startswith('autoentry'):
                logger.debug("{} is not valid, skipping".format(bug.get('id')))
                continue
            # Next assignee in the list, rotate
            if not dry_run:
                assignee = assign_list.pop()
                assign_list.insert(0, assignee)
            else:
                # dry_run does not rotate
                assignee = assign_list[0]
            bug_up = bugzilla.DotDict()
            bug_up.assigned_to = assignee
            bug_up.status = 'ASSIGNED'
            try:
                if not dry_run:
                    logger.info("Updating bug {} assigning {}".format(bug.get('id'), assignee))
                    bapi.put_bug(bug.get('id'), bug_up)
                else:
                    logger.info("Dry run, action not performed: would update bug {} assigning {}".format(bug.get('id'),
                                 assignee))
            except Exception as e:
                logging.debug("Failed to update bug {}: {}".format(bug.get('id'), e))

    except IndexError:
        logger.info("No unassigned bugs for component")

    with open(cfg.get('cache'), 'wb') as f:
        pickle.dump((assign_list, assign_hash), f)


if __name__ == "__main__":
    main()
