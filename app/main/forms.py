from flask_wtf import Form
from flask import session
from wtforms.validators import DataRequired, Email, Length, Regexp, EqualTo, IPAddress, Optional, NumberRange, ValidationError
from wtforms import StringField, SubmitField, PasswordField, SelectField, SelectMultipleField, DateTimeField, \
    RadioField, IntegerField, BooleanField, TextAreaField
from ..models import Role, Area, User
from ..my_func import get_machine_room_by_area, get_device_name


def check_workorder_login_name(form, field):
    print('123123123')
    if User.query.filter_by(workorder_login_name=field.data).all():
        print('1111')
        raise ValidationError('此工单用户名已存在')


class BaseForm(Form):
    machine_room_name = SelectField(label='请选择上联机房:')
    mac = StringField('请输入ONU MAC地址:', validators=[DataRequired(),
                                                   Regexp('^[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}',
                                                          0, '无效的MAC地址')])

    customer_number = StringField('请输入用户账号', validators=[DataRequired()])
    submit = SubmitField('提交')

    def __init__(self):
        super(BaseForm, self).__init__()
        self.machine_room_name.choices = get_machine_room_by_area(session.get('permit_machine_room'))


class FindByMacForm(Form):
    mac = StringField('请输入ONU MAC地址:', validators=[DataRequired(),
                                                   Regexp('^[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}',
                                                          0, '无效的MAC地址')])

    submit = SubmitField('提交')


class DeviceForm(Form):
    machine_room_name = SelectField(label='请选择上联机房:')
    device_name = StringField('device name', validators=[DataRequired()])
    ip = StringField('IP', validators=[DataRequired(), IPAddress()])
    login_name = StringField('Login Name', default='monitor')
    login_password = PasswordField('Login Password', default='shf-k61-906')
    enable_password = PasswordField('Enable Password')
    status = SelectField('Status', choices=[('1', '1'), ('2', '2'), ('3', '3')])
    submit = SubmitField('submit')

    def __init__(self):
        super(DeviceForm, self).__init__()
        print(session.get('permit_machine_room'))
        self.machine_room_name.choices = get_machine_room_by_area(session.get('permit_machine_room'))


class OntRegisterForm(Form):
    machine_room_name = SelectField(label='请选择上联机房:')
    mac = StringField('请输入ONU MAC地址:', validators=[DataRequired(),
                                                   Regexp('^[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}',
                                                          0, '无效的MAC地址,请注意末尾空格')])
    ont_vendor = SelectField('请选择光猫生产商',
                             validators=[DataRequired()],
                             choices=[('1', '华为'), ('2', '中兴'), ('3', 'TP-LINK'), ('4', '其它')],
                             default='1')
    ont_model_choice = SelectField(label='请选择光猫种类',
                                   choices=[('1', '单口'), ('2', '四口'), ('3', '标准模板')],
                                   validators=[DataRequired()],
                                   default='1')
    service_type = SelectField(label='请选择服务类型',
                               choices=[('1', '社区'), ('2', '商业'), ('3', '代理'), ('4', '联通')],
                               validators=[DataRequired()],
                               default='1')
    submit = SubmitField('提交')

    def __init__(self, machine_room_list):
        super(OntRegisterForm, self).__init__()
        if machine_room_list:
            self.machine_room_name.choices = machine_room_list
        else:
            self.machine_room_name.choices = get_machine_room_by_area(session.get('permit_machine_room'))


class OntRegisterFormByManager(Form):
    machine_room_name = SelectField(label='请选择上联机房:')
    mac = StringField('请输入ONU MAC地址:', validators=[DataRequired(),
                                                   Regexp('^[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}',
                                                          0, '无效的MAC地址,请注意末尾空格')])
    customer_number = StringField('请输入用户编号', validators=[DataRequired(),
                                              Regexp('^[A-Za-z]*[A-Za-z0-9]*$', 0,
                                                     '用户编号只能包括字母, 数字')])
    customer_distinct = StringField('请输入用户社区名(地址)', validators=[DataRequired()])
    ont_vendor = SelectField('请选择光猫生产商',
                             validators=[DataRequired()],
                             choices=[('1', '华为'), ('2', '中兴'), ('3', 'TP-LINK'), ('4', '其它')],
                             default='1')
    ont_model_choice = SelectField(label='请选择光猫种类',
                                   choices=[('1', '单口'), ('2', '四口'), ('3', '标准模板')],
                                   validators=[DataRequired()],
                                   default='1')
    service_type = SelectField(label='请选择服务类型',
                               choices=[('1', '社区'), ('2', '商业'), ('3', '代理')],
                               validators=[DataRequired()],
                               default='1')
    submit = SubmitField('提交')

    def __init__(self):
        super(OntRegisterFormByManager, self).__init__()
        self.machine_room_name.choices = get_machine_room_by_area(session.get('permit_machine_room'))


class RegistrationForm(Form):
    duty_choice = [('1', '组员'), ('2', '组长'), ('3', '大区经理'), ('4', '大区维护'), ('5', '网管'), ('6', '运维主管'), ('7', '电力工程师')]

    username = StringField('用户名', validators=[DataRequired(),
                                              Regexp('^[\u4E00-\u9FA5]*$', 0,
                                                     '用户名只能为中文 ')])
    email = StringField('邮箱', validators=[DataRequired(), Email(), Length(1, 64)])
    workorder_login_name = StringField('工单平台用户名')
    phoneNum = StringField('电话')
    password = PasswordField('请输入密码', validators=[DataRequired(), EqualTo('password2', message='请确认两次输入密码相同')])
    password2 = PasswordField('请再次输入密码', validators=[DataRequired(), ])
    role = SelectField('请选择角色', default='1')
    area = SelectField('所属大区', validators=[DataRequired()])
    machine_room_name = SelectMultipleField('请选择可管理的机房:', validators=[Optional()])
    # team = StringField('所属小组', validators=[DataRequired()])
    duty = SelectField('职务', validators=[DataRequired()], choices=duty_choice)
    submit = SubmitField('Register')

    def __init__(self):
        super(RegistrationForm, self).__init__()
        self.role.choices = [(str(k.id), k.name) for k in Role.query.all()]
        self.machine_room_name.choices = get_machine_room_by_area(session.get('permit_machine_room'))
        self.area.choices = [(str(a.id), a.area_name) for a in Area.query.all()]

    def validate_workorder_login_name(form, field):
        if User.query.filter_by(workorder_login_name=field.data).all():
            raise ValidationError('此工单用户名已存在')


class AreaConfigForm(Form):
    area_name = StringField('请输入大区名称:', validators=[DataRequired()])
    area_machine_room = SelectMultipleField('请选择可管辖机房', validators=[DataRequired()])
    submit = SubmitField('提交')

    def __init__(self):
        super(AreaConfigForm, self).__init__()
        self.area_machine_room.choices = get_machine_room_by_area(session.get('permit_machine_room'))


class CommuntiyMachineroomConfig(Form):
    community_name = StringField('请输社区名称:', validators=[DataRequired()])
    machine_room = SelectMultipleField('请选择上联机房', validators=[DataRequired()])
    submit = SubmitField('提交')

    def __init__(self):
        super(CommuntiyMachineroomConfig, self).__init__()
        self.machine_room.choices = get_machine_room_by_area(session.get('permit_machine_room'))


class OntRegisterInspector(Form):
    start_time = DateTimeField(label='统计开始时间:', validators=[Optional()], format='%Y-%m-%d %H:%M')
    stop_time = DateTimeField(label='统计结束时间:', validators=[Optional()], format='%Y-%m-%d %H:%M')
    machine_room_name = SelectMultipleField(label='请选择机房:')
    fsp = StringField(label='请输入f/s/p', validators=[Optional(), Regexp('^\d+/\d+/\d+', 0, '格式举例0/1/0')])
    cevlan = IntegerField(label='请输入内层VLAN', validators=[Optional(), NumberRange(min=1, max=4096)])
    area = SelectMultipleField(label='请选择大区')
    mac = StringField('请输入ONU MAC地址:', validators=[Optional(),
                                                   Regexp('[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}',
                                                          0, '无效的MAC地址')])
    customer_number = StringField('请输入用户编号', validators=[
                                                         Regexp('^[A-Za-z]*[A-Za-z0-9]*$', 0,
                                                                '用户编号只能包括字母, 数字')])
    customer_addr = StringField('请输入用户地址(建议模糊查询)', validators=[Optional()])
    ont_model_choice = SelectMultipleField(label='请选择光猫种类',
                                           choices=[('1', '单口'), ('2', '四口'), ('3', '标准模板')])
    submit = SubmitField('查询')

    def __init__(self):
        super(OntRegisterInspector, self).__init__()
        self.machine_room_name.choices = get_machine_room_by_area(session.get('permit_machine_room'))
        self.area.choices = self.get_area(session.get('LOGINAREA'))

    def get_area(self, loginarea):
        area_all = [(str(a.id), a.area_name) for a in Area.query.all()]
        loginarea_ = Area.query.filter_by(id=loginarea).first()
        if loginarea_ and loginarea_.area_machine_room == '0xffffffffff':
            return area_all
        else:
            if not loginarea:
                loginarea = 0
            area_name = dict(area_all)[str(loginarea)]
            print(area_name)
            return [(str(loginarea), area_name)]


class MaintainPevlanForm(Form):
    device_name = SelectField(label='请选择OLT设备:')
    pevlan = StringField(label='请输入外层VLAN:')
    service_type = SelectField(label='请选择服务类型',
                               choices=[('1', '社区'), ('2', '商业'), ('3', '代理'), ('4', '联通')],
                               validators=[DataRequired()],
                               default='1')
    submit = SubmitField('提交')

    def __init__(self):
        super(MaintainPevlanForm, self).__init__()
        self.device_name.choices = get_device_name()


class ManualSync(Form):
    device_name = SelectMultipleField(label='请选择OLT设备:')
    sync_action = RadioField(label='请选择同步内容:', choices=[('1', '同步CEVLAN'), ('2', '同步SERVICE PORT'),
                                                         ('3', '同步ONU基础信息'), ('4', '同步ONU光衰及下线原因'),
                                                         ('5', 'MAC LEARNED BY ONU')])
    submit = SubmitField('开始同步')

    def __init__(self):
        super(ManualSync, self).__init__()
        self.device_name.choices = get_device_name()


class OntAutoFindForm(Form):
    machine_room = SelectField(label='请选择机房:')
    submit = SubmitField('提交')

    def __init__(self):
        super(OntAutoFindForm, self).__init__()
        self.machine_room.choices = get_machine_room_by_area(session.get('permit_machine_room'))


class OltCheck(Form):
    machine_room = SelectMultipleField(label='请选择机房:')
    submit = SubmitField('提交')

    def __init__(self):
        super(OltCheck, self).__init__()
        self.machine_room.choices = get_machine_room_by_area(session.get('permit_machine_room'))


class AlterEponInterfaceForm(Form):
    source_machine_room = SelectMultipleField(label='请选择换口前机房:', validators=[DataRequired()])
    destincation_machine_room = SelectMultipleField(label='请选择目标机房:', validators=[DataRequired()])
    submit = SubmitField('查找')

    def __init__(self):
        super(AlterEponInterfaceForm, self).__init__()
        self.source_machine_room.choices = \
            self.destincation_machine_room.choices = \
            get_machine_room_by_area(session.get('permit_machine_room'))


class UserModal(Form):
    duty_choice = [('1', '组员'), ('2', '组长'), ('3', '大区经理'), ('4', '大区维护'), ('5', '网管'), ('0', None)]

    username = StringField('用户名', validators=[Regexp('^[\u4E00-\u9FA5]*$', 0,
                                                     '用户名只能为中文 ')])
    password = PasswordField('请输入密码')
    role = SelectField('请选择角色', default='0')
    area = SelectField('所属大区', default='0')
    machine_room_name = SelectMultipleField('请选择可管理的机房:')
    duty = SelectField('职务', choices=duty_choice, default='0')
    workorder_login_name = StringField('工单平台用户名', [DataRequired(), check_workorder_login_name])

    def __init__(self):
        super(UserModal, self).__init__()
        role_c = [(str(k.id), k.name) for k in Role.query.all()]
        role_c.append(('0', None))
        self.role.choices = role_c
        self.machine_room_name.choices = get_machine_room_by_area(session.get('permit_machine_room'))
        a = [(str(a.id), a.area_name) for a in Area.query.all()]
        a.append(('0', None))
        self.area.choices = a


class AreaModal(Form):
    area_name = StringField('大区名:')
    area_desc = StringField('大区描述:')
    machine_room_name = SelectMultipleField('请选择可管理的机房:')

    def __init__(self):
        super(AreaModal, self).__init__()
        self.machine_room_name.choices = get_machine_room_by_area(session.get('permit_machine_room'))


class PcapOrder(Form):
    accountId = StringField('用户编号', validators=[DataRequired()])
    question = TextAreaField('问题描述', validators=[DataRequired()])
    submit = SubmitField('提交')









