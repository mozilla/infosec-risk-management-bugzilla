import bugzilla
from config import Config
from assigner import Assigner
import random

test_config = Config('config.yaml')


class TestAssigner():
    def test_assigner_creation(self):
        assigner = Assigner(test_config.bmo_url(),
                            test_config.service("va"), True)
        assert isinstance(assigner, Assigner)
        assert isinstance(assigner.assignees, list)
        assert isinstance(assigner.api_key, str)
        assert isinstance(assigner.api, bugzilla.Bugzilla)
        assert assigner.dry_run == True

    def test_next_assignee(self):
        assigner = Assigner(test_config.bmo_url(),
                            test_config.service("va"), True)

        assignee = assigner.next_assignee()
        assert isinstance(assignee, str)
        assert assignee in test_config.service("va")['assignees']

    def test_get_terms(self):
        assigner = Assigner(test_config.bmo_url(),
                            test_config.service("va"), True)

        terms = assigner.get_terms()
        assert isinstance(terms, list)
        assert len(terms) == 4

        product = terms[0]
        assert product['product'] == 'Enterprise Information Security'

        component = terms[1]
        assert component['component'] == 'Vulnerability Assessment'

        new_status = terms[2]
        assert new_status['status'] == 'NEW'

        unconfirmed_status = terms[3]
        assert unconfirmed_status['status'] == 'UNCONFIRMED'
