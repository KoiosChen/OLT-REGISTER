from flask import current_app
from . import db
from flask_login import UserMixin, AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from . import login_manager


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Permission:
    FOLLOW = 0x01
    COMMENT = 0x02
    WRITE_ARTICLES = 0x04
    MODERATE_COMMENTS = 0x08
    REGION_SUPPORT = 0x10
    MAN_ON_DUTY = 0x20
    NETWORK_MANAGER = 0x40
    ADMINISTER = 0x80


class MachineRoom(db.Model):
    __tablename__ = 'machineroom_list'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(24), unique=True, nullable=False)
    address = db.Column(db.String(100), unique=True, nullable=False)
    level = db.Column(db.Integer, nullable=True)
    status = db.Column(db.Integer, nullable=False, default=1)
    permit_value = db.Column(db.String(200))
    devices = db.relationship('Device', backref='machine_room')

    def __repr__(self):
        return '<Machine Room %r>' % self.name


class Device(db.Model):
    __tablename__ = 'device_list'
    id = db.Column(db.Integer, primary_key=True)
    device_name = db.Column(db.String(30), unique=True, nullable=False)
    ip = db.Column(db.String(16), unique=True, nullable=False)
    login_name = db.Column(db.String(20), nullable=False)
    login_password = db.Column(db.String(20), nullable=False)
    machine_room_id = db.Column(db.Integer, db.ForeignKey('machineroom_list.id'))
    enable_password = db.Column(db.String(20), nullable=True)
    status = db.Column(db.Integer, nullable=False, default=1)
    ont_device = db.relationship('ONTDetail', backref='ont_device')

    def __repr__(self):
        return '<device name %r>' % self.device_name


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    @staticmethod
    def insert_roles():
        roles = {
            'User': (Permission.FOLLOW |
                     Permission.COMMENT |
                     Permission.WRITE_ARTICLES, True),
            'Moderator': (Permission.FOLLOW |
                          Permission.COMMENT |
                          Permission.WRITE_ARTICLES |
                          Permission.MODERATE_COMMENTS, False),
            'REGION': (Permission.FOLLOW |
                          Permission.COMMENT |
                          Permission.WRITE_ARTICLES |
                          Permission.MODERATE_COMMENTS |
                       Permission.REGION_SUPPORT, False),
            'MAN_ON_DUTY': (Permission.FOLLOW |
                       Permission.COMMENT |
                       Permission.WRITE_ARTICLES |
                       Permission.MODERATE_COMMENTS |
                       Permission.REGION_SUPPORT |
                            Permission.MAN_ON_DUTY, False),
            'SNOC': (Permission.FOLLOW |
                     Permission.COMMENT |
                     Permission.WRITE_ARTICLES |
                     Permission.MODERATE_COMMENTS |
                     Permission.REGION_SUPPORT |
                     Permission.MAN_ON_DUTY |
                     Permission.NETWORK_MANAGER, False),
            'Administrator': (0xff, False)
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Role %r>' % self.name


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    phoneNum = db.Column(db.String(15), unique=True)
    username = db.Column(db.String(64), index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    area = db.Column(db.Integer)
    duty = db.Column(db.Integer)
    permit_machine_room = db.Column(db.String(200))
    password_hash = db.Column(db.String(128))
    status = db.Column(db.SmallInteger)
    workorder_login_name = db.Column(db.String(20), unique=True, nullable=True)

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def can(self, permissions):
        return self.role is not None and \
               (self.role.permissions & permissions) == permissions

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)

    def is_moderate(self):
        return self.can(Permission.MODERATE_COMMENTS)

    def is_region(self):
        return self.can(Permission.REGION_SUPPORT)

    def is_manonduty(self):
        return self.can(Permission.MAN_ON_DUTY)

    def is_snoc(self):
        return self.can(Permission.NETWORK_MANAGER)

    def __repr__(self):
        return '<User %r>' % self.username


class ONTDetail(db.Model):
    __tablename__ = 'ont_detail'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device_list.id'), index=True)
    f = db.Column(db.String(2), index=True, nullable=False, default='0')
    s = db.Column(db.String(3), index=True, nullable=False)
    p = db.Column(db.String(3), index=True, default='')
    ont_id = db.Column(db.String(3), index=True, nullable=False)
    mac = db.Column(db.String(28), index=True, nullable=False)
    control_flag = db.Column(db.String(30))
    run_state = db.Column(db.String(30))
    config_state = db.Column(db.String(30))
    match_state = db.Column(db.String(30))
    protect_side = db.Column(db.String(10))
    rx_optical_power = db.Column(db.Float)
    temperature = db.Column(db.Float)
    voltage = db.Column(db.Float)
    olt_rx_ont_optical_power = db.Column(db.Float)
    last_down_cause = db.Column(db.String(30))
    last_up_time = db.Column(db.DateTime)
    last_down_time = db.Column(db.DateTime)
    line_profile_id = db.Column(db.String(20))
    line_profile_name = db.Column(db.String(20))
    server_profile_id = db.Column(db.String(20))
    server_profile_name = db.Column(db.String(20))
    ont_status = db.Column(db.SmallInteger, nullable=False, default=1)
    pre_id = db.Column(db.Integer, nullable=False, default=0)
    create_time = db.Column(db.DateTime, nullable=False)
    update_time = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return '<ONT MAC %r>' % self.mac


class AccountInfo(db.Model):
    __tablename__ = 'account'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, index=True)
    password = db.Column(db.String(40))
    interface = db.Column(db.String(10), index=True)
    sub_int = db.Column(db.String(5), index=True)
    ip = db.Column(db.String(20))
    mac = db.Column(db.String(30), index=True)
    bas_name = db.Column(db.String(20))
    create_time = db.Column(db.DateTime)
    update_time = db.Column(db.DateTime)

    def __repr__(self):
        return '<ACCOUNT INFO -> USERNAME: %r>' % self.username


class MacLearnedByONT(db.Model):
    __tablename__ = 'mac_learned_by_ont'
    id = db.Column(db.Integer, primary_key=True)
    ont_mac = db.Column(db.String(30), index=True, nullable=False)
    learned_mac = db.Column(db.String(30), index=True, nullable=True)
    ontinfo_id = db.Column(db.String(7), nullable=True)
    create_time = db.Column(db.DateTime)
    update_time = db.Column(db.DateTime)


class Log(db.Model):
    __tablename__ = 'log'
    id = db.Column(db.Integer, primary_key=True)
    operator = db.Column(db.String(64), index=True, nullable=False)
    machine_room_id = db.Column(db.Integer, nullable=False)
    mac = db.Column(db.String(28), nullable=False)
    customer_number = db.Column(db.String(64), nullable=False)
    type = db.Column(db.SmallInteger, nullable=False)
    create_time = db.Column(db.DateTime, nullable=False)


class OntRegister(db.Model):
    __tablename__ = 'ont_register'
    id = db.Column(db.Integer, primary_key=True)
    f = db.Column(db.String(2), index=True, nullable=False, default='0')
    s = db.Column(db.String(3), index=True, nullable=False)
    p = db.Column(db.String(3), index=True, default='')
    ont_id = db.Column(db.String(3), index=True, nullable=False)
    mac = db.Column(db.String(28), index=True, nullable=False)
    ontinfo_id = db.Column(db.Integer, nullable=True)
    ont_model = db.Column(db.String(20))
    cevlan = db.Column(db.String(5))
    device_id = db.Column(db.Integer)
    user_addr = db.Column(db.String(100))
    username = db.Column(db.String(30))
    regist_status = db.Column(db.SmallInteger)
    reporter_name = db.Column(db.String(32))
    reporter_group = db.Column(db.String(32))
    regist_operator = db.Column(db.String(32))
    remarks = db.Column(db.String(200))
    create_time = db.Column(db.DateTime)
    update_time = db.Column(db.DateTime)
    status = db.Column(db.SmallInteger)

    def __repr__(self):
        return '<ONT REGISTER INFO -> MAC: %r>' % self.mac


class CeVlan(db.Model):
    __tablename__ = 'cevlan'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer)
    f = db.Column(db.String(2), index=True, nullable=False, default='0')
    s = db.Column(db.String(3), index=True, nullable=False)
    p = db.Column(db.String(3), index=True, nullable=False)
    ont_id = db.Column(db.String(3), index=True, nullable=False)
    cevlan = db.Column(db.String(5), index=True, nullable=False)

    def __repr__(self):
        return '<CEVLAN INFO -> MAC: %r>' % self.cevlan


class AreaMachineRoom(db.Model):
    __tablename__ = 'area_machine_room'
    id = db.Column(db.Integer, primary_key=True)
    area_id = db.Column(db.Integer, index=True, nullable=False)
    permit_machine_room = db.Column(db.Integer, nullable=False)


class ServicePort(db.Model):
    __tablename__ = 'service_port'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer)
    f = db.Column(db.String(2), index=True, nullable=False, default='0')
    s = db.Column(db.String(3), index=True, nullable=False)
    p = db.Column(db.String(3), index=True, nullable=False)
    pevlan = db.Column(db.String(5), index=True, nullable=False)
    cevlan_range = db.Column(db.String(12), index=True, nullable=False)
    port_status = db.Column(db.String(5), index=True, nullable=False)
    update_time = db.Column(db.DateTime)

    def __repr__(self):
        return '<ServicePort INFO -> Device: %r>' % self.device_id


class Area(db.Model):
    __tablename__ = 'area'
    id = db.Column(db.Integer, primary_key=True)
    area_name = db.Column(db.String(30), index=True, nullable=False)
    area_desc = db.Column(db.String(200))
    area_machine_room = db.Column(db.String(200))

    def __repr__(self):
        return '<Area info: %r>' % self.area_name


class PeVlan(db.Model):
    __tablename__ = 'pevlan'
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer)
    pevlan = db.Column(db.String(5), index=True, nullable=False)
    service_type = db.Column(db.SmallInteger, default=1)
    update_time = db.Column(db.DateTime)

    def __repr__(self):
        return '<PEVlan INFO -> PE-vlan: %r>' % self.pevlan


class SyncEvent(db.Model):
    __tablename__ = 'sync_event'
    event_id = db.Column(db.Integer, primary_key=True)
    sub_id = db.Column(db.Integer, index=True)
    sync_func = db.Column(db.String(100), index=True)
    sync_device = db.Column(db.Integer)
    start_time = db.Column(db.DateTime)
    stop_time = db.Column(db.DateTime)
    sync_status = db.Column(db.SmallInteger)
    remark = db.Column(db.String(200), nullable=True)

    def __reduce__(self):
        return '<SyncEvent INFO -> %r>' % self.id + ' ' + self.sync_func


class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False


class ApiConfigure(db.Model):
    __tablename__ = 'api_configure'
    id = db.Column(db.Integer, primary_key=True)
    api_name = db.Column(db.String(20), nullable=False)
    api_params = db.Column(db.String(100), nullable=False)
    api_params_value = db.Column(db.String(200))


class Community(db.Model):
    __tablename__ = 'community'
    id = db.Column(db.Integer, primary_key=True)
    community_name = db.Column(db.String(50), nullable=False, index=True)
    machine_room_id = db.Column(db.Integer, index=True)


class RegisterModify(db.Model):
    __tablename__ = 'register_modify'
    id = db.Column(db.Integer, primary_key=True)
    from_id = db.Column(db.Integer, nullable=False, index=True)
    to_id = db.Column(db.Integer, nullable=False, index=True)
    modify_reason = db.Column(db.Integer, nullable=False, index=True)
    create_time = db.Column(db.DateTime, nullable=False)


login_manager.anonymous_user = AnonymousUser
path = '/Users/Peter/python/founderbn_nmp/app/config_file/'


PATH_PREFIX = '/Users/Peter/python/founderbn_nmp/app/'
CONFIG_FILE_PATH = PATH_PREFIX + 'config_file/'
UPLOAD_FOLDER = PATH_PREFIX + 'UploadFile/'
CACTI_PIC_FOLDER = PATH_PREFIX + '/static/cacti_pic/'

aes_key = 'koiosr2d2c3p0000'

ontinfo_translate = {'Run state': '运行状态',
                     'dying-gasp': '断电下线',
                     'online': '在线',
                     'offline': '离线',
                     'LOSi': '光的原因下线',
                     'Last down cause': '最后下线原因',
                     'Last up time': '最后上线时间',
                     'Last down time': '最后下线时间',
                     'Last dying gasp time': '最后断电时间',
                     'ONT mac address': '光猫MAC',
                     'Rx optical power(dBm)': '光猫收光(dBm)',
                     'Temperature(C)': '温度(C)',
                     'Voltage(V)': '电压(V)',
                     'OLT Rx ONT optical power(dBm)': 'OLT收光(dBm)',
                     'UpTime': '上线时间',
                     'DownTime': '下线时间',
                     'DownCause': '下线原因',
                     'ONT LOSi alarm': '光的原因下线',
                     'ONT LOSI alarm': '光的原因下线',
                     'ONT dying-gasp': '断电下线'}

defaultLoginName = 'chenjzh'


PERMIT_IP = ['all']