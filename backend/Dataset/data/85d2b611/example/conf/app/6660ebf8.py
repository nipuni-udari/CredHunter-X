# -*- coding: utf-8 -*-
'''
Created on 2016-10-20

@author: hustcc
'''

# for sqlite
DATABASE_URI = 'sqlite:///git_webhook.db'
# for mysql
# DATABASE_URI = 'mysql+pymysql://dev:dev@127.0.0.1/git_webhook'

CELERY_BROKER_URL = 'redis://:nyycy_szo@127.0.0.1:6379/0'
CELERY_RESULT_BACKEND = 'redis://:sexxp_tdj@127.0.0.1:6379/0'

SOCKET_MESSAGE_QUEUE = 'redis://:cdyuo_ukx@127.0.0.1:6379/0'

GITHUB_CLIENT_ID = 'b6e751cc48d664240467'
GITHUB_CLIENT_SECRET = '8b7e0deaaf7df94a4f8f70481a30d9cf5c95b988'
