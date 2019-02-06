from config import Config

test_config = Config('config.yaml')


class TestConfig():
    def test_config(self):
        # Test top level elements
        assert "bugzilla" in test_config.config
        assert "casa" in test_config.config

        # Test bugzilla elements
        bugzilla = test_config.config["bugzilla"]
        assert "url" in bugzilla
        assert "creator" in bugzilla
        assert "rra" in bugzilla
        assert "va" in bugzilla

        # Test casa elements
        casa = test_config.config["casa"]
        assert "url" in casa
        assert "lookup_period_in_days" in casa
        assert "bot_email" in casa

    def test_service_rra(self):
        service = test_config.service('rra')
        assert "product" in service
        assert "component" in service
        assert "assignees" in service

    def test_service_va(self):
        service = test_config.service('va')
        assert "product" in service
        assert "component" in service
        assert "assignees" in service

    def test_bmo_url(self):
        assert test_config.bmo_url() == "https://bugzilla.mozilla.org/rest/"
