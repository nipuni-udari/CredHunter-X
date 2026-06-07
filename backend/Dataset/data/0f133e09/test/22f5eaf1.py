import datetime
import json
import sys
import time  # NOQA
import unittest

import jwt
import requests  # NOQA

from github.GithubObject import GithubObject

private_key = """
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC+5ePolLv6VcWLp2f17g6r6vHl+eoLuodOOfUl8JK+MVmvXbPa
IjU0Gj8RpGEgJslb3EjSl++zHBmRrnRNvXCqIuPNt904J+qYSidAPtNnV/jWcz7g
cVzn4U/S5hLvcmHw9GfMmdMESq8Dq4lHh1Jujf8oY4kmsywUCTY2gB8hhLVspfgc
CLLqhzVF0GX8uV+206xhcNFKH+6NuLxJGidGY+2f8nXCgSSX3JmBr1QD6wsNxR/a
cq7DFXMgO9f/w2V/mPgnYE2ydxv+HKxpoWJwh0S4krGEiyVvfw2XBjTM/LwgAwvS
Qu6Dmytjnlg1ROZQkpgSWVLoiw8vvWEsAyS18FBnlAQfl01uRJSAHheid2wguPna
5BCcoOWoWlH0KPlsit4gw8xVv15oBmd7JaQcQoEjdizwe1Xjt8QvXIcUmbOoS8ff
SUN3mecBPONq6fu75kQ58tC3MOVIB4JNY1fnmptwKOfW3W88Ok09OOeZmkzQHDgS
8KMiKXAbBuNxFBJ6rvo9dM6mX1vQY6pSiwdqciXov8TR33laMQQ3PmJlRxMP/ku6
W9Vf6nQfqMVvJdzEY1l5LjBJlT8CnSUf139TgBpPbxavz/f7BSv+N+W64BlbAHxp
E2NugkXR0Bh3//eCN4vTc18eVfB7X1baz10GQjxGcRWkglH3ndu6LkhSkprb02XX
b0NQ9iDNaCt/mMvSv03XBmH8d+nd9wqRTu1u1R/1xvhg8Yw46QW9ulqd5N42G+NO
SGlyi1h/UDMWz2oJA1tAsEL4pezgVuLysp7xteHkCZJ=
-----END RSA PRIVATE KEY-----
"""

public_key = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+5ePolLv6VcWLp2f17g6r6vHl
+eoLuodOOfUl8JK+MVmvXbPaxDy0SS0pQhwTOMtB0VdSt++elklDCadeokhEoGDQ
p411o+kiOhzLxfakp/kewf4UHJnu4M/A2nHmxXVe2lzYnZvZHX5BM4SJo5PGdr0U
e2JtSXoAtYr6qE9maQIDAQAB
-----END PUBLIC KEY-----
"""


class GithubIntegration(unittest.TestCase):
    def setUp(self):
        # This flag ask requester to do some checking,
        # for debug and test purpose. But
        # `InstallationAuthorization.InstallationAuthorization` is a
        # `NonCompletableGithubObject`, it does not have requester.
        # So the check is not needed.
        # see `GithubIntegration.get_access_token`
        self.origin_check_after_init_flag = GithubObject.CHECK_AFTER_INIT_FLAG
        GithubObject.setCheckAfterInitFlag(False)

        self.origin_time = sys.modules["time"].time
        sys.modules["time"].time = lambda: 1550055331.7435968

        class Mock:
            def __init__(self):
                self.args = tuple()
                self.kwargs = dict()

            @property
            def status_code(self):
                return 201

            def json(self):
                return json.loads(self.text)

            @property
            def text(self):
                return (
                    '{"token": "e9.nq79471pn50511985155rzuf0b9g5m7430gy7994",'
                    '"expires_at": "2019-02-13T11:10:38Z"}'
                )

            def __call__(self, *args, **kwargs):
                self.args = args
                self.kwargs = kwargs
                return self

        self.origin_request_post = sys.modules["requests"].post
        self.mock = Mock()
        sys.modules["requests"].post = self.mock

        class GetMock:
            def __init__(self):
                self.args = tuple()
                self.kwargs = dict()
                self.calls = []

            @property
            def status_code(self):
                return 201

            def json(self):
                return json.loads(self.text)

            @property
            def text(self):
                return (
                    '{"id":111111,"account":{"login":"foo","id":11111111,'
                    '"node_id":"foobar",'
                    '"avatar_url":"https://avatars3.githubusercontent.com/u/11111111?v=4",'
                    '"gravatar_id":"","url":"https://api.github.com/users/foo",'
                    '"html_url":"https://github.com/foo",'
                    '"followers_url":"https://api.github.com/users/foo/followers",'
                    '"following_url":"https://api.github.com/users/foo/following{/other_user}",'
                    '"gists_url":"https://api.github.com/users/foo/gists{/gist_id}",'
                    '"starred_url":"https://api.github.com/users/foo/starred{/owner}{/repo}",'
                    '"subscriptions_url":"https://api.github.com/users/foo/subscriptions",'
                    '"organizations_url":"https://api.github.com/users/foo/orgs",'
                    '"repos_url":"https://api.github.com/users/foo/repos",'
                    '"events_url":"https://api.github.com/users/foo/events{/privacy}",'
                    '"received_events_url":"https://api.github.com/users/foo/received_events",'
                    '"type":"Organization","site_admin":false},"repository_selection":"all",'
                    '"access_tokens_url":"https://api.github.com/app/installations/111111/access_tokens",'
                    '"repositories_url":"https://api.github.com/installation/repositories",'
                    '"html_url":"https://github.com/organizations/foo/settings/installations/111111",'
                    '"app_id":11111,"target_id":11111111,"target_type":"Organization",'
                    '"permissions":{"issues":"write","pull_requests":"write","statuses":"write","contents":"read",'
                    '"metadata":"read"},"events":["pull_request","release"],"created_at":"2019-04-17T16:10:37.000Z",'
                    '"updated_at":"2019-05-03T06:27:48.000Z","single_file_name":null}'
                )

            def __call__(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                self.args = args
                self.kwargs = kwargs
                return self

        self.origin_request_get = sys.modules["requests"].get
        self.get_mock = GetMock()
        sys.modules["requests"].get = self.get_mock

    def testCreateJWT(self):
        from github import GithubIntegration

        integration = GithubIntegration(25216, private_key)
        token = integration.create_jwt()
        payload = jwt.decode(
            token,
            key=public_key,
            algorithms=["RS256"],
            options={"verify_exp": False},
        )
        self.assertDictEqual(
            payload, {"iat": 1550055331, "exp": 1550055391, "iss": 25216}
        )

    def testGetAccessToken(self):
        from github import GithubIntegration

        integration = GithubIntegration(25216, private_key)
        auth_obj = integration.get_access_token(664281)
        self.assertEqual(
            self.mock.args[0],
            "https://api.github.com/app/installations/664281/access_tokens",
        )
        self.assertEqual(auth_obj.token, "v1.ce63424bc55028318325caac4f4c3a5378ca0038")
        self.assertEqual(
            auth_obj.expires_at, datetime.datetime(2019, 2, 13, 11, 10, 38)
        )
        self.assertEqual(
            repr(auth_obj), "InstallationAuthorization(expires_at=2019-02-13 11:10:38)"
        )

    def test_get_installation(self):
        from github import GithubIntegration

        integr = GithubIntegration("11111", private_key)
        inst = integr.get_installation("foo", "bar")
        self.assertEqual(
            self.get_mock.calls[0][0],
            ("https://api.github.com/repos/foo/bar/installation",),
        )
        self.assertEqual(inst.id, 111111)

    def test_get_installation_custom_base_url(self):
        from github import GithubIntegration

        integr = GithubIntegration("11111", private_key, base_url="https://corp.com/v3")
        inst = integr.get_installation("foo", "bar")
        self.assertEqual(
            self.get_mock.calls[0][0],
            ("https://corp.com/v3/repos/foo/bar/installation",),
        )
        self.assertEqual(inst.id, 111111)

    def tearDown(self):
        GithubObject.setCheckAfterInitFlag(self.origin_check_after_init_flag)
        sys.modules["time"].time = self.origin_time
        sys.modules["requests"].post = self.origin_request_post
        sys.modules["requests"].get = self.origin_request_get
