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


def _setup_logging(logger=logging.getLogger(__name__), debug=True):
    """
    Setup default logging
    It can be overloaded by passing a premade logger
    """
    # Logging
    formatstr = "[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
    loghandlers = [logging.handlers.SysLogHandler(address="/dev/log")]
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
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode and prints debug messages")
    parser.add_argument("--dry-run", action="store_true", help="Perform all read operations, and no write operations")
    parser.add_argument("--configfile", default="config.yaml", help="Config file for this program")
    parser.add_argument("--module", default="va,rra,casa", help="Choose which module to run, such as va, rra, or casa")

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
    bapi_key = os.environ.get("BUGZILLA_API_KEY")

    if bapi_key is None:
        logger.critical("No Bugzilla API Key passed in environment variable BUGZILLA_API_KEY")
        sys.exit(127)

    bapi = bugzilla.Bugzilla(url=url, api_key=bapi_key)
    return bapi


def _setup_casa_api(url):
    """
    Setup the CASA/Biztera API object
    """
    capi_key = os.environ.get("CASA_API_KEY")

    if capi_key is None:
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

    bcfg_va = bcfg.get("va")
    bcfg_rra = bcfg.get("rra")

    # Look for bugs that are up to ccfg.lookup_period_in_days days old
    lookup_period = (datetime.now() - timedelta(days=ccfg.get("lookup_period_in_days"))).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Look for all registered products, for that lookup_period
    terms = [
        {"product": bcfg_va.get("product")},
        {"product": bcfg_rra.get("product")},
        {"component": bcfg_va.get("component")},
        {"component": bcfg_rra.get("component")},
        {"last_change_time": lookup_period},
        {"creator": ccfg.get("bot_email")},
    ]
    bugs = bapi.search_bugs(terms)["bugs"]
    logger.debug("Analyzing {} bugs...".format(len(bugs)))

    for bug in bugs:
        logger.debug("Processing bug {}...".format(bug.get("id")))
        # Get casa project id and other metadata
        comments = bapi.get_comments(bug.get("id"))["bugs"][str(bug.get("id"))]["comments"]
        casa_data = capi.parse_casa_comment(comments[0]["text"])
        project_id = casa_data.get("project_id")
        if (len(casa_data)) == 0:
            logger.warning("Could not find any CASA data in comment 0 even thus this comment was created by CASA!")
            continue

        # STEP 1
        # Some basic checks that we can update that project
        ## Have bugzilla support?
        casa_project = capi.casa_get_project(casa_data.get("project_id"))
        if casa_project["syncedToIntegrations"].get("bugzilla") is not True:
            logger.warning("Project {} has no bugzilla integration, skipping!".format(project_id))
            continue

        # Ensure this project cares about security and thus has a security tab/channel
        if (casa_project.get("securityPrivacy") is None) or (casa_project["securityPrivacy"].get("security") is None):
            logger.warning("Project {} has no securityPrivacy.security component, skipping!".format(project_id))
            continue

        # Set a shorthands for our tab
        casa_project_security = casa_project["securityPrivacy"]["security"]
        casa_status = casa_project_security.get("status")

        # STEP 2
        # Is already approved/disapproved in some way?
        ## This means Bugzilla cannot override a status already set to done
        ## It will override "none" or "rejected" as necessary
        if casa_status["decision"] == "rejected" and not (bug.get("resolution") in ["WONTFIX", "INCOMPLETE"]):
            logger.warning(
                "Project {} already has a security status set ({}), but we're allowing override".format(
                    project_id, casa_status["decision"]
                )
            )
            pass
        elif casa_status["decision"] != "none":
            logger.warning(
                "Project {} already has a security status set ({}) and this cannot be reverted, skipping!".format(
                    project_id, casa_status["decision"]
                )
            )
            continue

        # XXX Temporary fix so that we do not re-set none status which can trigger email notifications,
        # until INVALID/DUPLICATE get their own status
        if casa_status["decision"] == "none" and (bug.get("resolution") in ["INVALID", "DUPLICATE"]):
            logger.warning("Project {} is already in status 'none' and will not be modified".format(project_id))
            continue

        # STEP 3
        # Check who's to be assigned to the project in Casa
        ## Only try this if the assignee looks like a Mozilla-corp email as we know this will otherwise fail
        delegator_id = None
        if bug.get("assigned_to").endswith("@mozilla.com"):
            try:
                delegator = capi.find_delegator(bug.get("assigned_to"))
            except IndexError:
                delegator = None
                logger.warning("No CASA delegator for Bugzilla user {}".format(bug.get("assigned_to")))
            else:
                delegator_id = delegator.get("id")

        try:
            deciding_approver = casa_status["decidingApprover"]["id"]
        except TypeError:
            # It's possible that the decidingApprover is empty in Casa
            deciding_approver = None
            logger.debug("No decidingApprover id present in CASA, internally setting deciding_approver to None")

        ## If lookup failed in any way, use whomever is already assigned by Casa
        if delegator_id is None:
            logger.warning(
                "Could not match Bugzilla assignee: {} with Casa, " "using defaults".format(bug.get("assigned_to"))
            )
            delegator_id = deciding_approver
            # Everything failed, we have no one to assign to. Warn and skip..
            if delegator_id is None:
                logger.warning(
                    "Could not find a valid delegator_id, this means we don't know whom to delegate to. "
                    "Project {} will NOT be assigned in CASA (skipping).".format(project_id)
                )
                continue
        elif delegator_id != deciding_approver:
            ## Set the new assignee if lookup worked
            if not dry_run:
                res = capi.set_delegator(project_id, delegator_id)
                logger.info(
                    "Setting new assignee/delegator in CASA to {} ({}) for project {}".format(
                        delegator_id, bug.get("assigned_to"), project_id
                    )
                )
            else:
                logger.info(
                    "Would attempt to set assignee/delegator in CASA to {} ({}) for project {}"
                    "(dry run prevented this)".format(delegator_id, bug.get("assigned_to"), project_id)
                )
        else:
            logger.info(
                "Assignee/delegator in CASA is already correct, no changes made "
                "{} ({}) for project {})".format(delegator_id, bug.get("assigned_to"), project_id)
            )

        # STEP 4
        # The project also needs to be in approverReview step/state in order for us to be able to set a delegator, so
        # ensure that here
        if casa_project_security["status"].get("step") != "approverReview":
            logger.info(
                "Project {} is not in approverReview state ({})".format(project_id, casa_project_security["status"])
            )
            if not dry_run:
                capi.set_project_step(project_id, channel="security", step="approverReview")
            else:
                logger.debug("Would set project {} step to approverReview (dry_run prevented this)".format(project_id))

        # STEP 5
        # Update the project status if the bug has been closed in some way
        if bug.get("status") in ["RESOLVED", "VERIFIED", "CLOSED"]:
            if not dry_run:
                if bug.get("resolution") in ["WONTFIX", "INCOMPLETE"]:
                    needinfo = {"requestee": bcfg.get("needinfo"), "name": "needinfo", "status": "?", "type_id": 800}
                    bug_up = bugzilla.DotDict()
                    bug_up.flags = [needinfo]
                    bapi.put_bug(bug.get("id"), bug_up)
                    # Override delegator to the risk manager if needed
                    try:
                        ts_delegator = capi.find_delegator(bcfg.get("needinfo"))
                        delegator_id = ts_delegator.get("id")
                        # Set the new delegator here so that casa_set_status() works for this delegator_id
                        # This is because Biztera will reset the project status when the delegator is changed, but also
                        # does not allow changing the project status with "another" delegator. This means the steps must
                        # always be:
                        # 1) change delegator (this will reset status)
                        # 2) change project status to the desired status
                        capi.set_delegator(project_id, delegator_id)
                    except IndexError:
                        logger.warning(
                            "No CASA delegator for Bugzilla user {}, using previous delegator".format(
                                bcfg.get("needinfo")
                            )
                        )
                    logger.info(
                        "Will inform risk manager {} of resolution state for bug {} "
                        "(and delegate CASA ticket to this user)".format(bcfg.get("needinfo"), bug.get("id"))
                    )
                res = capi.casa_set_status(project_id, delegator_id, bug.get("resolution"))
                logger.info(
                    "CASA API Updated status for project {} to {}: {} (delegator: {})".format(
                        project_id, bug.get("resolution"), res, delegator_id
                    )
                )
            else:
                logger.info(
                    "Would attempt to set status {} on project {} for bug {}{}"
                    " (dry run prevented this)".format(
                        bug.get("resolution"), casa_data.get("url"), bcfg.get("url")[:-5], bug.get("id")
                    )
                )
                if bug.get("resolution") in ["WONTFIX", "INCOMPLETE"]:
                    logger.info(
                        "Would have informed risk manager {} of resolution state for bug {}".format(
                            bcfg.get("needinfo"), bug.get("id")
                        )
                    )
        else:
            logger.debug(
                "Would not set CASA status because this bug is not in a resolved state yet: "
                "{}{}".format(bcfg.get("url")[:-5], bug.get("id"))
            )

    logger.debug("Casa analysis completed")


def autoassign(bapi, capi, bcfg, ccfg, fcfg, dry_run):
    """
    This will search through unassigned bugs and assign them automatically.
    @bcfg: bugzilla configuration dict
    @ccfg: casa configuration dict
    @fcfg: foxsec configuration dict
    """
    global logger

    reset_assignees = False  # Controls if we're going to rewrite the cache that record who's the next assignee or not
    foxsec_keywords = fcfg.get("keywords")
    try:
        with open(bcfg.get("cache"), "rb") as f:
            (assign_list, assign_hash) = pickle.load(f)
            if set(assign_list) != set(cfg.get("assignees")):
                logger.info("List of assignees changed, resetting list!")
                reset_assignees = True
    except FileNotFoundError:
        reset_assignees = True

    if reset_assignees:
        assign_hash = bcfg.get("assignees")
        assign_list = assign_hash[:]
        logger.info("Configuring defaults for the NEW assignment list: {}".format(assign_hash))

    # Do we have any bugs in the queue?
    terms = [
        {"product": bcfg.get("product")},
        {"component": bcfg.get("component")},
        {"status": "NEW"},
        {"status": "UNCONFIRMED"},
    ]

    try:
        bugs = bapi.search_bugs(terms)["bugs"]
    except Exception as e:
        logger.warning("Fatal: Bugzilla search query failed, will not auto-assign bugs: {}".format(e))
        return

    try:
        bugzilla.DotDict(bugs[-1])
        logger.debug("Found {} unassigned bug(s). Assigning work!".format(len(bugs)))
        for bug in bugs:
            # Is this a valid request bug?
            if bug.get("whiteboard").startswith("autoentry"):
                logger.debug("{} is not valid, skipping".format(bug.get("id")))
                continue
            # Next assignee in the list, rotate
            if not dry_run:
                assignee = assign_list.pop()
                assign_list.insert(0, assignee)
            else:
                # dry_run does not rotate
                assignee = assign_list[0]

            # Is this a CASA bug or manual RRA request?
            if bug.get("creator") == ccfg.get("bot_email"):
                # This is bug sync'ed from CASA, look for "Product Line" in first comment
                comments = bapi.get_comments(bug.get("id"))["bugs"][str(bug.get("id"))]["comments"]
                casa_comment = capi.parse_casa_comment(comments[0]["text"])
                product_line = casa_comment.get("product_line")
                # If it has "Product Line: Firefox" then this should be assigned to FoxSec
                if "firefox" in product_line.lower():
                    # This is a Firefox-related project/vendor, should be handled by FoxSec
                    # TODO: Change the email address later
                    assignee = fcfg.get("assignee")
            # RRA requested manually in Bugzilla
            else:
                comment_0 = bapi.get_comments(bug.get("id"))["bugs"][str(bug.get("id"))]["comments"][0]["text"]
                foxsec_rra = False
                if any(keyword.lower() in comment_0 for keyword in foxsec_keywords):
                    foxsec_rra = True
                    break
                # This is a Firefox-related project/vendor, should be handled by FoxSec
                # TODO: Change the email address later
                assignee = fcfg.get("assignee")

            bug_up = bugzilla.DotDict()
            bug_up.assigned_to = assignee
            bug_up.status = "ASSIGNED"
            try:
                if not dry_run:
                    logger.info("Updating bug {} assigning {}".format(bug.get("id"), assignee))
                    bapi.put_bug(bug.get("id"), bug_up)
                else:
                    logger.info(
                        "Dry run, action not performed: would update bug {} assigning {}".format(
                            bug.get("id"), assignee
                        )
                    )
            except Exception as e:
                logging.debug("Failed to update bug {}: {}".format(bug.get("id"), e))

    except IndexError:
        logger.info("No unassigned bugs for component")

    with open(bcfg.get("cache"), "wb") as f:
        pickle.dump((assign_list, assign_hash), f)


def main():
    global logger
    args = _parse_args()
    logger = _setup_logging(debug=args.debug)
    config = _load_config(args.configfile)
    bapi = _setup_bugzilla_api(config["bugzilla"]["url"])
    capi = _setup_casa_api(config["casa"]["url"])

    modules = args.module.split(",")
    logger.debug("Selected modules to run: {}".format(modules))

    if "rra" in modules:
        autoassign(bapi, capi, config["bugzilla"]["rra"], config["casa"], config["foxsec"], args.dry_run)
    if "va" in modules:
        autoassign(bapi, capi, config["bugzilla"]["va"], config["casa"], config["foxsec"], args.dry_run)
    if "casa" in modules:
        autocasa(bapi, capi, config["bugzilla"], config["casa"], args.dry_run)


if __name__ == "__main__":
    main()
