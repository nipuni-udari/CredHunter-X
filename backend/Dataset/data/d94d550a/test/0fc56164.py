from allauth.socialaccount.tests import OAuth2TestsMixin
from allauth.tests import MockedResponse, TestCase

from .provider import ShareFileProvider


class ShareFileTests(OAuth2TestsMixin, TestCase):
    provider_id = ShareFileProvider.id

    def get_mocked_response(self):
        return MockedResponse(
            200,
            """
        {"access_token": "00444733aadeab",
         "refresh_token": "60522779efeaac",
         "token_type": "bearer",
         "expires_in": 28800,
         "appcp": "sharefile.com",
         "apicp": "sharefile.com",
         "subdomain": "example",
         "access_files_folders": true,
         "modify_files_folders": true,
         "admin_users": true,
         "admin_accounts": true,
         "change_my_settings": true,
          "web_app_login": true}
        """,
        )
