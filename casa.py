import json
import requests


class DotDict(dict):
    """dict.item notation for dict()'s"""

    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class Casa:
    """
    Class to communicate with the Biztera/CASA API
    """

    def __init__(self, url, api_key):
        self.api_key = api_key
        if url[-1] != "/":
            url = url + "/"
        self.url = url
        self.headers = {"content-type": "application/json", "Authorization": "Bearer " + self.api_key}
        self.api_max_retries = 3

    def _get(self, q, params=""):
        """
        Wrapper for get
        """

        if q[-1] == "/":
            q = q[:-1]

        retries = 0

        while retries < self.api_max_retries:
            r = requests.get("{url}{q}?{params}".format(url=self.url, q=q, params=params), headers=self.headers)
            retries = retries + 1
            if r.ok:
                break

        if not r.ok:
            raise Exception(r.url, r.reason, r.status_code, r.text)
        return DotDict(r.json())

    def _post(self, q, payload="", params=""):
        """
        Wrapper for post
        """

        if q[-1] == "/":
            q = q[:-1]
        payload_json = json.dumps(payload)

        retries = 0

        while retries < self.api_max_retries:
            r = requests.post("{url}{q}".format(url=self.url, q=q), headers=self.headers, data=payload_json)
            retries = retries + 1
            if r.ok:
                break

        if not r.ok:
            raise Exception(r.url, r.reason, r.status_code, payload_json, r.text)

        if len(r.text) == 0:
            ret = {"result": "ok"}
        else:
            ret = DotDict(r.json())

        return ret

    def parse_casa_comment(self, comment):
        """
        Parses the CASA/Biztera first comment format
        @comment: str
        """

        lines = comment.split("\n")
        parse_next = ""
        parsed = {}

        for l in lines:
            # Anything setup for us?
            if parse_next == "url":
                parsed["url"] = l.split("- ")[1]
                parsed["project_id"] = parsed.get("url").split("/")[-1]
            elif parse_next == "creator":
                parsed["creator"] = l.split("- ")[1]

            # Setup next-line parser
            if l == "Biztera URL:":
                parse_next = "url"
            elif l == "Project Creator:":
                parse_next = "creator"
            else:
                parse_next = None

        return parsed

    def casa_get_project(self, project_id):
        """
        Gets Casa project JSON
        @project_id int a Casa project id
        """
        return self._get("projects/{}".format(project_id))

    def casa_set_status(self, project_id, delegator_id, bug_resolution):
        """
        Sets CASA status depending on bug resolution
        @project_id: str Casa project id
        @delegator_id: str Casa delegator id
        @bug_resolution: str of bugzilla resolution state

        Resolution in CASA is either: done, rejected, or none
        Resolution label in CASA is custom: 'Pending', 'Do not use', 'Warning: Outstanding issues, refer to the RRA',
        'Completed: no outstanding issues found'
        Resolution in Bugzilla is either: FIXED, INVALID, WONTFIX, DUPLICATE, WORKSFORME or INCOMPLETE

        See also `decision_map` below
        """
        # Map decision bugzilla=>(casa decision label, casa decision)
        decision_map = {
            "FIXED": ("Completed: No outstanding issues found", "done"),
            "INVALID": ("Pending", "none"),
            "DUPLICATE": ("Pending", "none"),
            "WONTFIX": ("Do not use", "rejected"),
            "INCOMPLETE": ("Warning: Outstanding issues, refer to the RRA", "done"),
        }
        decisionLabel, decision = decision_map.get(bug_resolution)

        # Set it
        payload = {"delegatorId": delegator_id, "decision": decision, "decisionLabel": decisionLabel}
        return self._post("projects/{}/channels/security".format(project_id), payload=payload)

    def find_delegator(self, bugzilla_email):
        """
        Find the delegator id by trying to match a bugzilla user mail to Casa's
        Note that we only return the first match and expect it is correct, though this is not actually guaranteed.
        @bugzilla_email str Bugzilla user's email
        """

        return self._get("users/search", params="q={}".format(bugzilla_email)).get("results")[0]

    def set_delegator(self, project_id, delegator_id):
        """
        Set the delegator id to the project (ie assign)
        @project_id str Casa project id
        @delegator_id str Casa user identifier for the delegator/assignee
        """

        payload = {"approverIds": [delegator_id]}
        return self._post("projects/{}/channels/security".format(project_id), payload=payload)

    def set_project_step(self, project_id, channel="security", step="approverReview"):
        """
        Set the project step (state). If not set to approverReview for example, it's not possible to modify the project
        (set delegator, etc.)
        @project_id str Casa project id
        @channel str the project channel
        @step str Casa project step
        """

        valid_steps = ["approverReview", "moderatorReview"]  # This could-should also be an enum/object
        if step not in valid_steps:
            raise Exception("InvalidStepValue")
        payload = {"step": step}
        return self._post("projects/{}/channels/{}".format(project_id, channel), payload=payload)
