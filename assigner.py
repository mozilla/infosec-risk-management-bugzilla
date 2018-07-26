#!/usr/bin/env python
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Copyright (c) 2016-2018 Mozilla Corporation

import argparse
import bugzilla
import casa
from datetime import datetime, timedelta
import logging, logging.handlers
import pickle
import requests
import sys
import yaml
import os

def _setup_logging(logger = logging.getLogger(__name__), debug=True):
    """
    Setup default logging
    It can be overloaded by passing a premade logger
    """
    # Logging
    formatstr="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
    loghandlers = [logging.handlers.SysLogHandler(address='/dev/log')]
    if debug:
        logger.setLevel(logging.DEBUG)
        loghandlers.append(logging.StreamHandler(stream=sys.stderr))
    else:
        logger.setLevel(logging.INFO)
    logging.basicConfig(format=formatstr, datefmt="%H:%M:%S", handlers=loghandlers)
    return logger


def _parse_args(parser=argparse.ArgumentParser()):
    """
    Default argument parser
    It can be overloaded by passing a premade parser
    """
    # Arguments
    parser.add_argument('-d', '--debug', action="store_true", help='Enable debug mode and prints debug messages')
    parser.add_argument('--dry-run', action="store_true", help='Perform all read operations, and no write operations')
    parser.add_argument('--configfile', default="config.yaml", help='Config file for this program')

    args = parser.parse_args()
    return args


def _load_config(path):
    """
    Config loader, takes a yaml file
    """
    config = {}
    try:
        with open(path) as fd:
            config = yaml.load(fd)
    except Exception as e:
        logger.critical("Could not parse configuration file: {}".format(e))
        sys.exit(127)
    return config


def _setup_bugzilla_api(url):
    """
    Setup the bugzilla API object
    """
    bapi_key = os.environ.get('BUGZILLA_API_KEY')

    if (bapi_key is None):
        logger.critical("No Bugzilla API Key passed in environment variable BUGZILLA_API_KEY")
        sys.exit(127)

    bapi = bugzilla.Bugzilla(url=url, api_key=bapi_key)
    return bapi


def _setup_casa_api(url):
    """
    Setup the CASA/Biztera API object
    """
    capi_key = os.environ.get('CASA_API_KEY')

    if (capi_key is None):
        logger.critical("No CASA API Key passed in environment variable CASA_API_KEY")
        sys.exit(127)

    capi = casa.Casa(url=url, api_key=capi_key)
    return capi


def autocasa(bapi, capi, bcfg, ccfg, dry_run):
    """
    This will search through bugs and update CASA accordingly.
    @bcfg: bugzilla configuration dict
    @ccfg: casa configuration dict
    """

    bcfg_va = bcfg.get('va')
    bcfg_rra = bcfg.get('rra')

    # Look for bugs that are up to ccfg.lookup_period_in_days days old
    lookup_period = (datetime.now() - timedelta(days=ccfg.get('lookup_period_in_days'))).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Look for all registered products, for that lookup_period
    terms = [{'product': bcfg_va.get('product')}, {'product': bcfg_rra.get('product')},
             {'component': bcfg_va.get('component')}, {'component': bcfg_rra.get('component')},
             {'last_change_time': lookup_period},
             {'creator': ccfg.get('bot_email')}
            ]
    bugs = bapi.search_bugs(terms)['bugs']
    logger.debug('Analyzing {} bugs...'.format(len(bugs)))

    for bug in bugs:
        # Get casa project id and other metadata
        comments = bapi.get_comments(bug.get('id'))['bugs'][str(bug.get('id'))]['comments']
        casa_data = capi.parse_casa_comment(comments[0]['text'])
        project_id = casa_data.get('project_id')
        if (len(casa_data)) == 0:
            logger.warning("Could not find any CASA data in comment 0 even thus this comment was created by CASA!")
            continue

        # Some basic checks that we can update that project
        ## Have bugzilla support?
        casa_project = capi.casa_get_project(casa_data.get('project_id'))
        if casa_project['syncedToIntegrations']['bugzilla'] is not True:
            logger.warning('Project {} has no bugzilla integration, skipping!'.format(project_id))
            continue

        # Is already approved/disapproved in some way?
        ## XXX This means Bugzilla cannot override a status already set, thus, if you set "WONTFIX" in bugzilla,
        ## then later "FIXED" this will NOT be reflected
        casa_status = casa_project['securityPrivacy']['security']['status']
        if casa_status['decision'] != 'none':
            logger.warning('Project {} already has a security status set ({}), skipping!'.format(project_id,
                           casa_status['decision']))
            continue

        # XXX Temporary fix so that we do not re-set none status which can trigger email notifications,
        # until INVALID/DUPLICATE get their own status
        if casa_status['decision'] == 'none' and (bug.get('resolution') in ['INVALID', 'DUPLICATE']):
            logger.warning('Project {} is already in status \'none\' and will not be modified'.format(project_id))
            continue

        # Check who's to be assigned to the project in Casa
        ## Only try this if the assignee looks like a Mozilla-corp email as we know this will otherwise fail
        delegator_id = None
        if bug.get('assigned_to').endswith('@mozilla.com'):
            delegator = capi.find_delegator(bug.get('assigned_to'))
            delegator_id = delegator.get('id')

        ## If lookup failed in any way, use whomever is already assigned by Casa
        if delegator_id is None:
            logger.warning("Could not match Bugzilla assignee: {} with Casa, "
                           "using defaults".format(bug.get('assigned_to')))
            delegator_id = casa_status['decidingApprover']['id']
        elif (delegator_id != casa_status['decidingApprover']['id']):
            ## Set the new assignee if lookup worked
            if not dry_run:
                res = capi.set_delegator(project_id, delegator_id)
                logger.info("Setting new assignee/delegator in CASA to {} ({}) for project {}".format(delegator_id,
                                                                                               bug.get('assigned_to'),
                                                                                               project_id))
            else:
                logger.info("Would attempt to set assignee/delegator in CASA to {} ({}) for project {}",
                            "(dry run prevented this)".format(delegator_id, bug.get('assigned_to'), project_id))
        else:
            logger.info("Assignee/delegator in CASA is already correct, no changes made "
                        "{} ({}) for project {})".format(delegator_id, bug.get('assigned_to'), project_id))

        # Update the project status if the bug has been closed in some way
        if bug.get('status') in ['RESOLVED', 'VERIFIED', 'CLOSED'] :
            if not dry_run:
                res = capi.casa_set_status(project_id, delegator_id, bug.get('resolution'))
                logger.info("CASA API Updated status for project {} to {}: {}".format(project_id,
                                                                                      bug.get('resolution'),
                                                                                      res))
            else:
                logger.info('Would attempt to set status {} on project {} for bug {}{}'
                            ' (dry run prevented this)'
                            .format(bug.get('resolution'), casa_data.get('url'), bcfg.get('url')[:-5], bug.get('id')))
        else:
            logger.debug("Would not set CASA status because this bug is not in a resolved state yet: "
                         "{}{}".format(bcfg.get('url')[:-5], bug.get('id')))

    logger.debug('Casa analysis completed')


def autoassign(bapi, cfg, dry_run):
    """
    This will search through unassigned bugs and assign them automatically.
    @cfg: bugzilla configuration dict
    """
    global logger

    reset_assignees = False # Controls if we're going to rewrite the cache that record who's the next assignee or not
    try:
        with open(cfg.get('cache'), 'rb') as f:
            (assign_list, assign_hash) = pickle.load(f)
            if set(assign_list) != set(cfg.get('assignees')):
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

    try:
        bugs = bapi.search_bugs(terms)['bugs']
    except Exception as e:
        logger.warning('Fatal: Bugzilla search query failed, will not auto-assign bugs: {}'.format(e))
        return

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


def main():
    global logger
    args = _parse_args()
    logger = _setup_logging(debug=args.debug)
    config = _load_config(args.configfile)
    bapi = _setup_bugzilla_api(config['bugzilla']['url'])
    capi = _setup_casa_api(config['casa']['url'])

    autoassign(bapi, config['bugzilla']['rra'], args.dry_run)
    autoassign(bapi, config['bugzilla']['va'], args.dry_run)
    autocasa(bapi, capi, config['bugzilla'], config['casa'], args.dry_run)


if __name__ == "__main__":
    main()
