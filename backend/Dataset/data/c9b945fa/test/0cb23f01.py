from __future__ import unicode_literals, print_function
import unittest
import sys
import requests
from io import StringIO

from oauthlib.oauth1 import SIGNATURE_TYPE_QUERY, SIGNATURE_TYPE_BODY
from oauthlib.oauth1 import SIGNATURE_RSA, SIGNATURE_PLAINTEXT
from requests_oauthlib import OAuth1Session

try:
    import mock
except ImportError:
    from unittest import mock

try:
    import cryptography
except ImportError:
    cryptography = None

try:
    import jwt
except ImportError:
    jwt = None

if sys.version[0] == "3":
    unicode_type = str
else:
    unicode_type = unicode


TEST_RSA_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEogIBAAKCAQEApF1JaMSN8TEsh4N4O/5SpEAVLivJyLH+Cgl3OQBPGgJrP6KA\n"
    "57GZUr+8zHr+QpRQbvdo1/TAUhnnYmukvX1Gs1VoRIe9q9qAmF2+X4SZmEhPw6bP\n"
    "EP8k6Z0c7zPCP+OEuJL30vv8mCNi+ay51FubBxJPsxfZvh70L8KPyNjbaoqB8CGR\n"
    "PGBZFJIWXAVwc608tw8nvkZ4AAI6Ik4KPIGIIjYWdRQjyiG7H2hPIQZWGY85063M\n"
    "i61D3/o5P103L4qDZfJffTHDVx1Xj2oLuoBITwVZbpScdILqFTf3yrDAos+eLd7d\n"
    "74RJq5sQONYaJJHeaceqAnKphD+O9VT14PnGcrGtvuFNFhDruKCvXKqWdvmJ4jlG\n"
    "XVUqQDnT4fZiFbsJcU+x39Gqzo3pNk7sArfmUAe+6qCIyz0KKShZywiVlYQifohU\n"
    "XVBvbdRwsN7mi5Nqb8Ne7dhzWHPjlvxslrVIZD1u+5Bjv0aOwzKIo3Z1StSAUiZ4\n"
    "LzXJU03tbndTmRyZbd5R9Fu9fr06qeeG+PrHGJ8kLNKb4uNs2CsdCVtL8qTtrAep\n"
    "kyy7moBbeiys8LP8nEURk6bdIYb7V2MrsJ0VWRDUgnTiDL77AUtsbhz4IFpikXc0\n"
    "BuKubzXSo18AUJ2/ej2pYPdTsIihPZnpgbMCeMq9nePx+fEKbLy5rPPcGPVBLmRv\n"
    "izqgE9buUBQi7A7bsZAFQn10V2/KseKHGAhTtrKZ5P9B2Wik6BEjpO8GIZjpqqmc\n"
    "KbBJ3X80JELZjzABxE4Ue1tkyFIzEeAATGO4r90eDhlqZ+RLnIB8E1p08ZWnuFo2\n"
    "bqI2OSXfDfjaIxgBu2RsY697AkQ0gA4vM5chEJTMjGMzreTt3eFFXFLAvhvyTsM+\n"
    "9MKkeFIMp6VexvcGi6sOWKZxIPJkn4yFXPbjGVGH809kz8jSauPv/tBc0tmKT30N\n"
    "gxrvkWTpT2WqY7dNQ6dhmbaawct8RIM/sLMS49hR1GCMV7NirL91W3eDvuw9VS6W\n"
    "RCJPXverNy/fTY2Enq/bJIcgS7vk066WcOYJLN9cWboK/SPyP3e26sdybT8ZgbXa\n"
    "r4y+e8Os/PDcpS76f+0aTpiNNZiXLTjFa8pP+x1DzfWG6t1BO/JnhCRtLpxx/hOU\n"
    "NRel765BxKqxs9tsRhLUpETWG8TspIFULDPq320QhdjNVXT1f3uc33qbw3710Kif\n"
    "rtkLWVuzcxraj3fY0IkoWEWPzFDDoQWZJDdgFeuQmF6HblU4CxUS9crnMgNkX8R3\n"
    "xdb5lbzQ/CYjwRs/nY7J3tjTJslPv7iGWBdHvmW85ptntWqZOR6ENkjRhKeS+Kya\n"
    "QzNGTxShcindGS4Z9/15jgt/O2UPBemrQbj77rnRknItvxkH01ifH4nzr+W7Yhvp\n"
    "nyPBwylRvO10GqXTAjJHis05FyHiJyJGJF5z3VN75ENBdOOWNYmVofgINiLV3aTv\n"
    "0smnFSsDetG+ZbefRUHS+jVxPlhlYh6Ec4piHFY9uyhfmC1eQys3elOrzk6T8FTr\n"
    "iFZMFPa8aR3DZ71eDOZX4MXdvjc9+dIeD8SdOknRuh6a+lK2QbU=\n"
    "-----END RSA PRIVATE KEY-----"
)

TEST_RSA_OAUTH_SIGNATURE = (
    "j8WF8PGjojT82aUDd2EL%2Bz7HCoHInFzWUpiEKMCy%2BJ2cYHWcBS7mXlmFDLgAKV0"
    "P%2FyX4TrpXODYnJ6dRWdfghqwDpi%2FlQmB2jxCiGMdJoYxh3c5zDf26gEbGdP6D7O"
    "Ssp5HUnzH6sNkmVjuE%2FxoJcHJdc23H6GhOs7VJ2LWNdbhKWP%2FMMlTrcoQDn8lz"
    "%2Fb24WsJ6ae1txkUzpFOOlLM8aTdNtGL4OtsubOlRhNqnAFq93FyhXg0KjzUyIZzmMX"
    "9Vx90jTks5QeBGYcLE0Op2iHb2u%2FO%2BEgdwFchgEwE5LgMUyHUI4F3Wglp28yHOAM"
    "jPkI%2FkWMvpxtMrU3Z3KN31WQ%3D%3D"
)


class OAuth1SessionTest(unittest.TestCase):
    def test_signature_types(self):
        def verify_signature(getter):
            def fake_send(r, **kwargs):
                signature = getter(r)
                if isinstance(signature, bytes):
                    signature = signature.decode("utf-8")
                self.assertIn("oauth_signature", signature)
                resp = mock.MagicMock(spec=requests.Response)
                resp.cookies = []
                return resp

            return fake_send

        header = OAuth1Session("foo")
        header.send = verify_signature(lambda r: r.headers["Authorization"])
        header.post("https://i.b")

        query = OAuth1Session("foo", signature_type=SIGNATURE_TYPE_QUERY)
        query.send = verify_signature(lambda r: r.url)
        query.post("https://i.b")

        body = OAuth1Session("foo", signature_type=SIGNATURE_TYPE_BODY)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        body.send = verify_signature(lambda r: r.body)
        body.post("https://i.b", headers=headers, data="")

    @mock.patch("oauthlib.oauth1.rfc5849.generate_timestamp")
    @mock.patch("oauthlib.oauth1.rfc5849.generate_nonce")
    def test_signature_methods(self, generate_nonce, generate_timestamp):
        if not cryptography:
            raise unittest.SkipTest("cryptography module is required")
        if not jwt:
            raise unittest.SkipTest("pyjwt module is required")

        generate_nonce.return_value = "abc"
        generate_timestamp.return_value = "123"

        signature = 'OAuth oauth_nonce="abc", oauth_timestamp="123", oauth_version="1.0", oauth_signature_method="HMAC-SHA1", oauth_consumer_key="foo", oauth_signature="j7zNeVXbbvri3e5NHczYheYXxJT%3D"'
        auth = OAuth1Session("foo")
        auth.send = self.verify_signature(signature)
        auth.post("https://i.b")

        signature = 'OAuth oauth_nonce="abc", oauth_timestamp="123", oauth_version="1.0", oauth_signature_method="PLAINTEXT", oauth_consumer_key="foo", oauth_signature="%26"'
        auth = OAuth1Session("foo", signature_method=SIGNATURE_PLAINTEXT)
        auth.send = self.verify_signature(signature)
        auth.post("https://i.b")

        signature = (
            "OAuth "
            'oauth_nonce="abc", oauth_timestamp="123", oauth_version="1.0", '
            'oauth_signature_method="RSA-SHA1", oauth_consumer_key="foo", '
            'oauth_signature="{sig}"'
        ).format(sig=TEST_RSA_OAUTH_SIGNATURE)
        auth = OAuth1Session(
            "foo", signature_method=SIGNATURE_RSA, rsa_key=TEST_RSA_KEY
        )
        auth.send = self.verify_signature(signature)
        auth.post("https://i.b")

    @mock.patch("oauthlib.oauth1.rfc5849.generate_timestamp")
    @mock.patch("oauthlib.oauth1.rfc5849.generate_nonce")
    def test_binary_upload(self, generate_nonce, generate_timestamp):
        generate_nonce.return_value = "abc"
        generate_timestamp.return_value = "123"
        fake_xml = StringIO("hello world")
        headers = {"Content-Type": "application/xml"}
        signature = 'OAuth oauth_nonce="abc", oauth_timestamp="123", oauth_version="1.0", oauth_signature_method="HMAC-SHA1", oauth_consumer_key="foo", oauth_signature="m8qIdVVkigjp2i3KDkbOzhIDkPE%3D"'
        auth = OAuth1Session("foo")
        auth.send = self.verify_signature(signature)
        auth.post("https://i.b", headers=headers, files=[("fake", fake_xml)])

    @mock.patch("oauthlib.oauth1.rfc5849.generate_timestamp")
    @mock.patch("oauthlib.oauth1.rfc5849.generate_nonce")
    def test_nonascii(self, generate_nonce, generate_timestamp):
        generate_nonce.return_value = "abc"
        generate_timestamp.return_value = "123"
        signature = 'OAuth oauth_nonce="abc", oauth_timestamp="123", oauth_version="1.0", oauth_signature_method="HMAC-SHA1", oauth_consumer_key="foo", oauth_signature="X0ddnzz6JJTDboWmDZnvwyBh6k7%3D"'
        auth = OAuth1Session("foo")
        auth.send = self.verify_signature(signature)
        auth.post("https://i.b?cjk=%E5%95%A6%E5%95%A6")

    def test_authorization_url(self):
        auth = OAuth1Session("foo")
        url = "https://example.comm/authorize"
        token = "otsmur351cz"
        auth_url = auth.authorization_url(url, request_token=token)
        self.assertEqual(auth_url, url + "?oauth_token=" + token)

    def test_parse_response_url(self):
        url = "https://i.b/callback?oauth_token=foo&oauth_verifier=bar"
        auth = OAuth1Session("foo")
        resp = auth.parse_authorization_response(url)
        self.assertEqual(resp["oauth_token"], "foo")
        self.assertEqual(resp["oauth_verifier"], "bar")
        for k, v in resp.items():
            self.assertIsInstance(k, unicode_type)
            self.assertIsInstance(v, unicode_type)

    def test_fetch_request_token(self):
        auth = OAuth1Session("foo")
        auth.send = self.fake_body("oauth_token=foo")
        resp = auth.fetch_request_token("https://example.com/token")
        self.assertEqual(resp["oauth_token"], "foo")
        for k, v in resp.items():
            self.assertIsInstance(k, unicode_type)
            self.assertIsInstance(v, unicode_type)

    def test_fetch_request_token_with_optional_arguments(self):
        auth = OAuth1Session("foo")
        auth.send = self.fake_body("oauth_token=foo")
        resp = auth.fetch_request_token(
            "https://example.com/token", verify=False, stream=True
        )
        self.assertEqual(resp["oauth_token"], "foo")
        for k, v in resp.items():
            self.assertIsInstance(k, unicode_type)
            self.assertIsInstance(v, unicode_type)

    def test_fetch_access_token(self):
        auth = OAuth1Session("foo", verifier="bar")
        auth.send = self.fake_body("oauth_token=foo")
        resp = auth.fetch_access_token("https://example.com/token")
        self.assertEqual(resp["oauth_token"], "foo")
        for k, v in resp.items():
            self.assertIsInstance(k, unicode_type)
            self.assertIsInstance(v, unicode_type)

    def test_fetch_access_token_with_optional_arguments(self):
        auth = OAuth1Session("foo", verifier="bar")
        auth.send = self.fake_body("oauth_token=foo")
        resp = auth.fetch_access_token(
            "https://example.com/token", verify=False, stream=True
        )
        self.assertEqual(resp["oauth_token"], "foo")
        for k, v in resp.items():
            self.assertIsInstance(k, unicode_type)
            self.assertIsInstance(v, unicode_type)

    def _test_fetch_access_token_raises_error(self, auth):
        """Assert that an error is being raised whenever there's no verifier
        passed in to the client.
        """
        auth.send = self.fake_body("oauth_token=foo")
        with self.assertRaises(ValueError) as cm:
            auth.fetch_access_token("https://example.com/token")
        self.assertEqual("No client verifier has been set.", str(cm.exception))

    def test_fetch_token_invalid_response(self):
        auth = OAuth1Session("foo")
        auth.send = self.fake_body("not valid urlencoded response!")
        self.assertRaises(
            ValueError, auth.fetch_request_token, "https://example.com/token"
        )

        for code in (400, 401, 403):
            auth.send = self.fake_body("valid=response", code)
            with self.assertRaises(ValueError) as cm:
                auth.fetch_request_token("https://example.com/token")
            self.assertEqual(cm.exception.status_code, code)
            self.assertIsInstance(cm.exception.response, requests.Response)

    def test_fetch_access_token_missing_verifier(self):
        self._test_fetch_access_token_raises_error(OAuth1Session("foo"))

    def test_fetch_access_token_has_verifier_is_none(self):
        auth = OAuth1Session("foo")
        del auth._client.client.verifier
        self._test_fetch_access_token_raises_error(auth)

    def test_token_proxy_set(self):
        token = {
            "oauth_token": "fake-key",
            "oauth_token_secret": "fake-secret",
            "oauth_verifier": "fake-verifier",
        }
        sess = OAuth1Session("foo")
        self.assertIsNone(sess._client.client.resource_owner_key)
        self.assertIsNone(sess._client.client.resource_owner_secret)
        self.assertIsNone(sess._client.client.verifier)
        self.assertEqual(sess.token, {})

        sess.token = token
        self.assertEqual(sess._client.client.resource_owner_key, "fake-key")
        self.assertEqual(sess._client.client.resource_owner_secret, "fake-secret")
        self.assertEqual(sess._client.client.verifier, "fake-verifier")

    def test_token_proxy_get(self):
        token = {
            "oauth_token": "fake-key",
            "oauth_token_secret": "fake-secret",
            "oauth_verifier": "fake-verifier",
        }
        sess = OAuth1Session(
            "foo",
            resource_owner_key=token["oauth_token"],
            resource_owner_secret=token["oauth_token_secret"],
            verifier=token["oauth_verifier"],
        )
        self.assertEqual(sess.token, token)

        sess._client.client.resource_owner_key = "different-key"
        token["oauth_token"] = "different-key"

        self.assertEqual(sess.token, token)

    def test_authorized_false(self):
        sess = OAuth1Session("foo")
        self.assertIs(sess.authorized, False)

    def test_authorized_false_rsa(self):
        signature = (
            "OAuth "
            'oauth_nonce="abc", oauth_timestamp="123", oauth_version="1.0", '
            'oauth_signature_method="RSA-SHA1", oauth_consumer_key="foo", '
            'oauth_signature="{sig}"'
        ).format(sig=TEST_RSA_OAUTH_SIGNATURE)
        sess = OAuth1Session(
            "foo", signature_method=SIGNATURE_RSA, rsa_key=TEST_RSA_KEY
        )
        sess.send = self.verify_signature(signature)
        self.assertIs(sess.authorized, False)

    def test_authorized_true(self):
        sess = OAuth1Session("key", "secret", verifier="bar")
        sess.send = self.fake_body("oauth_token=foo&oauth_token_secret=bar")
        sess.fetch_access_token("https://example.com/token")
        self.assertIs(sess.authorized, True)

    @mock.patch("oauthlib.oauth1.rfc5849.generate_timestamp")
    @mock.patch("oauthlib.oauth1.rfc5849.generate_nonce")
    def test_authorized_true_rsa(self, generate_nonce, generate_timestamp):
        if not cryptography:
            raise unittest.SkipTest("cryptography module is required")
        if not jwt:
            raise unittest.SkipTest("pyjwt module is required")

        generate_nonce.return_value = "abc"
        generate_timestamp.return_value = "123"
        signature = (
            "OAuth "
            'oauth_nonce="abc", oauth_timestamp="123", oauth_version="1.0", '
            'oauth_signature_method="RSA-SHA1", oauth_consumer_key="foo", '
            'oauth_verifier="bar", oauth_signature="{sig}"'
        ).format(sig=TEST_RSA_OAUTH_SIGNATURE)
        sess = OAuth1Session(
            "key",
            "secret",
            signature_method=SIGNATURE_RSA,
            rsa_key=TEST_RSA_KEY,
            verifier="bar",
        )
        sess.send = self.fake_body("oauth_token=foo&oauth_token_secret=bar")
        sess.fetch_access_token("https://example.com/token")
        self.assertIs(sess.authorized, True)

    def verify_signature(self, signature):
        def fake_send(r, **kwargs):
            auth_header = r.headers["Authorization"]
            if isinstance(auth_header, bytes):
                auth_header = auth_header.decode("utf-8")
            self.assertEqual(auth_header, signature)
            resp = mock.MagicMock(spec=requests.Response)
            resp.cookies = []
            return resp

        return fake_send

    def fake_body(self, body, status_code=200):
        def fake_send(r, **kwargs):
            resp = mock.MagicMock(spec=requests.Response)
            resp.cookies = []
            resp.text = body
            resp.status_code = status_code
            return resp

        return fake_send
