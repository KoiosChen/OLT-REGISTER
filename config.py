import os
from datetime import datetime, timedelta

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SESSION_TYPE = 'redis'
    SESSION_KEY_PREFIX = 'flask_session:'
    SESSION_PERMANENT = True
    SESSION_USE_SIGNER = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=10)

    # SQLALCHEMY_POOL_SIZE = 300
    FLASKY_ADMIN = 'peter.chen@mbqianbao.com'

    # FLASKY_ADMIN = os.environ.get('FLASKY_ADMIN')

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    DB_USERNAME = os.environ.get('DEV_DATABASE_USERNAME') or 'peter'
    DB_PASSWORD = os.environ.get('DEV_DATABASE_PASSWORD') or '123123'
    DB_HOST = os.environ.get('DEV_DATABASE_HOST') or '127.0.0.1'
    DB_DATABASE = os.environ.get('DEV_DATABASE_DATABASE') or 'founderbn_sh'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://' + DB_USERNAME + ':' + DB_PASSWORD + '@' + DB_HOST + '/' + DB_DATABASE


class TestingConfig(Config):
    DEBUG = False
    DB_USERNAME = os.environ.get('TEST_DATABASE_USERNAME') or 'peter'
    DB_PASSWORD = os.environ.get('TEST_DATABASE_PASSWORD') or '123123'
    DB_HOST = os.environ.get('TEST_DATABASE_HOST') or '127.0.0.1'
    DB_DATABASE = os.environ.get('TEST_DATABASE_DATABASE') or 'founderbn_sh'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://' + DB_USERNAME + ':' + DB_PASSWORD + '@' + DB_HOST + '/' + DB_DATABASE

    JOBS = [

        {
            'id': 'sync_cevlan',
            'func': 'app.my_func:manual_sync_func',
            'args': ('1', range(1, 40)),
            'trigger': 'cron',
            'hour': '15',
            'minute': '45',
            'start_date': '2016-08-13 00:41:10'
        },

        {
            'id': 'tick',
            'func': 'app.my_func:tick',
            'args': (),
            'trigger': 'cron',
            'hour': '15',
            'minute': '41',
            'start_date': '2016-08-13 00:41:10'
        },

        {
            'id': 'sync_service_port',
            'func': 'app.my_func:manual_sync_func',
            'args': ('2', range(1, 40)),
            'trigger': 'cron',
            'hour': '15',
            'minute': '43',
            'start_date': '2016-08-13 00:41:10'
        },

        {
            'id': 'sync_ont_detail',
            'func': 'app.my_func:manual_sync_func',
            'args': ('6', range(1, 40)),
            'trigger': 'cron',
            'hour': '16',
            'minute': '15',
            'start_date': '2016-08-13 00:41:10'
        },

        {
            'id': 'save_config',
            'func': 'app.my_func:manual_sync_func',
            'args': ('7', range(1, 40)),
            'trigger': 'cron',
            'hour': '16',
            'minute': '15',
            'start_date': '2016-08-13 00:41:10'
        }

    ]

    SCHEDULER_VIEWS_ENABLED = True


class ProductionConfig(Config):
    DB_USERNAME = os.environ.get('DATABASE_USERNAME') or 'peter'
    DB_PASSWORD = os.environ.get('DATABASE_PASSWORD') or '123123'
    DB_HOST = os.environ.get('DATABASE_HOST') or '127.0.0.1'
    DB_DATABASE = os.environ.get('DATABASE_DATABASE') or 'founderbn_sh'
    UPLOAD_FILE = '/Users/Peter/python/flasky/result/'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://' + DB_USERNAME + ':' + DB_PASSWORD + '@' + DB_HOST + '/' + DB_DATABASE


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
