from allauth.socialaccount.tests import OAuth2TestsMixin
from allauth.tests import MockedResponse, TestCase

from .provider import DataportenProvider


class DataportenTest(OAuth2TestsMixin, TestCase):
    provider_id = DataportenProvider.id

    def setUp(self):
        super(DataportenTest, self).setUp()
        self.mock_data = {
            "userid": "19f8b950-1d85-902f-0bd9-0b83ba11451d",
            "userid_sec": ["feide:andreas@uninett.no"],
            "name": "Andreas \u00c5kre Solberg",
            "email": "andreas.solberg@uninett.no",
            "profilephoto": "p:d2849798-737c-42b5-a9ba-dae4d52ef987",
            "groups": [{}],
        }

    def get_login_response_json(self, with_refresh_token=True):
        rt = ""
        if with_refresh_token:
            rt = ',"refresh_token": "testrf"'
        return (
            """{
            "access_token":"testac",
            "expires_in":3600,
            "scope": "userid profile groups"
            %s
        }"""
            % rt
        )

    def get_mocked_response(self):
        return MockedResponse(
            status_code=200,
            content="""{
                "user": {
                    "userid": "32a7d300-3c90-438c-2ea9-6a96dc61946b",
                    "userid_sec": ["feide:andreas@uninett.no"],
                    "name": "Andreas \u00c5kre Solberg",
                    "email": "andreas.solberg@uninett.no",
                    "profilephoto": "p:e1192590-388f-17f2-f7ed-eaf3c40bf801"
                },
                "audience": "app123id"
            }""",
            headers={"content-type": "application/json"},
        )

    def test_extract_uid(self):
        uid = self.provider.extract_uid(self.mock_data)
        self.assertEqual(uid, self.mock_data["userid"])

    def test_extract_extra_data(self):
        # All the processing is done in the complete_login view, and thus
        # the data should be returned unaltered
        extra_data = self.provider.extract_extra_data(self.mock_data)
        self.assertEqual(extra_data, self.mock_data)

    def test_extract_common_fields(self):
        # The main task of this function is to parse the data in order to
        # find the Feide username, and if not, use the email
        common_fields = self.provider.extract_common_fields(self.mock_data)
        self.assertEqual(common_fields["username"], "andreas")

        # Test correct behaviour when Feide username is unavailable
        new_mock_data = dict(self.mock_data)
        new_mock_data["userid_sec"] = []
        new_common_fields = self.provider.extract_common_fields(new_mock_data)
        self.assertEqual(new_common_fields["username"], "andreas.solberg")
