# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from allauth.socialaccount.providers import registry
from allauth.socialaccount.tests import create_oauth2_tests
from allauth.tests import MockedResponse

from .provider import FeishuProvider


class FeishuTests(create_oauth2_tests(registry.by_id(FeishuProvider.id))):
    def get_mocked_response(self):
        return [
            MockedResponse(
                0,
                """
                {"data": {"access_token": "testac"}}
                """,
            ),
            MockedResponse(
                0,
                """
                {
                    "code": 0,
                    "data": {
                        "access_token": "j-6J7FtObX6MZO4JeGCWvvzm",
                        "avatar_url": "www.feishu.cn/avatar/icon",
                        "avatar_thumb": "www.feishu.cn/avatar/icon_thumb",
                        "avatar_middle": "www.feishu.cn/avatar/icon_middle",
                        "avatar_big": "www.feishu.cn/avatar/icon_big",
                        "expires_in": 7140,
                        "name": "zhangsan",
                        "en_name": "Three Zhang",
                        "open_id": "ou-caecc734c2e3328a62489fe0648c4b98779515d3",
                        "tenant_key": "577606c61nmv696d",
                        "refresh_expires_in": 2591940,
                        "refresh_token": "wr-e1QHbSMtLnJhJU4a04Hedx",
                        "token_type": "Bearer"
                    }
                }
                """,
            ),
        ]

    def get_login_response_json(self, with_refresh_token=True):
        return """{"app_access_token":"testac"}"""
