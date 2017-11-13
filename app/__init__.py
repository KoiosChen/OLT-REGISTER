from flask import Flask
from flask_bootstrap import Bootstrap
from flask_mail import Mail
from flask_moment import Moment
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from config import config
from flask_apscheduler import APScheduler
from flask_session import Session
import logging
import redis

# 用于存放监控记录信息，例如UPS前序状态，需要配置持久化
redis_db = redis.Redis(host='localhost', port=6379, db=7)

bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
db = SQLAlchemy()
login_manager = LoginManager()
scheduler = APScheduler()
sess = Session()
login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'


logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %H:%M:%S')
logger = logging.getLogger()
hdlr = logging.FileHandler("log.txt")
formatter = logging.Formatter(fmt='%(asctime)s - %(module)s-%(funcName)s - %(levelname)s - %(message)s',
                              datefmt='%m/%d/%Y %H:%M:%S')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)


def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)

    bootstrap.init_app(app)
    sess.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.app = app
    db.init_app(app)
    db.create_scoped_session()
    login_manager.init_app(app)
    scheduler.init_app(app)
    scheduler.start()

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    return app
