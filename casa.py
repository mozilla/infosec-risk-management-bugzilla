import json
import requests

class DotDict(dict):
    '''dict.item notation for dict()'s'''
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

class Casa:
    """
    Class to communicate with the Biztera/CASA API
    """
    def __init__(self, url, api_key):
        self.api_key = api_key
        if (url[-1] != '/'): url = url+'/'
        self.url = url
        self.headers = {'content-type': 'application/json',
                        'Authorization': 'Bearer '+self.api_key}

    def _get(self, q, params=''):
        """
        Wrapper for get
        """

        if (q[-1] == '/'): q = q[:-1]

        r = requests.get('{url}{q}?{params}'.format(url=self.url, q=q, params=params),
                headers=self.headers)

        if (not r.ok):
            raise Exception(r.url, r.reason, r.status_code, r.text)
        return DotDict(r.json())

    def _post(self, q, payload='', params=''):
        """
        Wrapper for post
        """

        if (q[-1] == '/'): q = q[:-1]

        r = requests.post('{url}{q}'.format(url=self.url, q=q),
                        headers=self.headers, data=payload)

        if (not r.ok):
            raise Exception(r.url, r.reason, r.status_code, payload, r.text)
        return DotDict(r.json())

    def parse_casa_comment(self, comment):
        """
        Parses the CASA/Biztera first comment format
        @comment: str
        """

        lines = comment.split('\n')
        parse_next = ''
        parsed = {}

        for l in lines:
            # Anything setup for us?
            if parse_next == 'url':
                parsed['url'] = l.split('- ')[1]
                parsed['project_id'] = parsed.get('url').split('/')[-1]
            elif parse_next == 'creator':
                parsed['creator'] = l.split('- ')[1]

            # Setup next-line parser
            if l == 'Biztera URL:':
                parse_next = 'url'
            elif l == 'Project Creator:':
                parse_next = 'creator'
            else:
                parse_next = None

        return parsed

    def casa_get_project(self, project_id):
        """
        Gets Casa project JSON
        @project_id int a Casa project id
        """
        return self._get('projects/{}'.format(project_id))

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
                         'FIXED': ('Completed: No oustanding issues found', 'done'),
                         'INVALID': ('Pending', 'none'),
                         'DUPLICATE': ('Pending', 'none'),
                         'WONTFIX': ('Do not use', 'rejected'),
                         'INCOMPLETE': ('Warning: )utstanding issues, refer to the RRA', 'done'),
                         'FIXED': ('Completed: No outstanding issues found', 'done')
                       }
        decisionLabel, decision = decision_map.get(bug_resolution)

        # Set it
        payload = {'delegatorId': delegator_id, 'decision': decision, 'decisionLabel': decisionLabel }
        return self._post('projects/{}/channels/security'.format(project_id), payload=payload)

    def set_delegator(self, projectid, bugzilla_user):
        """
        Sets the delegator id for a project
        @projectid str Casa project id
        @bugzilla_user str Bugzilla user's email
        """

        # XXX this is not done yet
        return None
