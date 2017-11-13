from flask import redirect, session, url_for, render_template, flash, request, jsonify
from flask_login import login_required
from ..models import Device, ONTDetail, Log, MachineRoom, Permission, User, OntRegister, PeVlan, Area, Role, \
    ontinfo_translate, Community, defaultLoginName
from ..decorators import admin_required, permission_required
from ..my_func import *
from .. import db, logger
from .forms import *
from . import main
import time
import re
from collections import defaultdict
from sqlalchemy import desc, or_
import json
from ..MyModule.SeqPickle import get_pubkey, update_crypted_licence
from ..MyModule.OntStatus import ont_status
from ..MyModule.GetWorkorderInfo import *


def get_device_info(machine_room_id):
    """
    :param machine_room_id:
    :return:
    """
    device_info = Device.query.filter_by(machine_room_id=machine_room_id).all()
    logger.debug('device list: {} '.format(device_info))
    return device_info if device_info else False


@main.route('/add_device', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def add_device():
    form = DeviceForm()
    if form.validate_on_submit():
        logger.info(
            'User {} add device on machine room {}'.format(session.get('LOGINNAME'), form.machine_room_name.data))
        try:
            device = Device(device_name=form.device_name.data,
                            ip=form.ip.data,
                            login_name='monitor',
                            login_password='shf-k61-906',
                            enable_password='',
                            machine_room=MachineRoom.query.filter_by(id=form.machine_room_name.data).first(),
                            status=form.status.data)
            db.session.add(device)
            db.session.commit()
            logger.info('User {} add device {}  in machine room {} successful'.
                        format(session.get('LOGINNAME'), form.device_name.data,
                               MachineRoom.query.filter_by(id=form.machine_room_name.data).first()))
            flash('Add Successful')
        except Exception as e:
            # 但是此处不能捕获异常
            logger.error('User {} add device {}  in machine room {} fail, because {}'.
                         format(session.get('LOGINNAME'), form.device_name.data,
                                MachineRoom.query.filter_by(id=form.machine_room_name.data).first(), e))
            flash('Add device fail')
        return redirect(url_for('.add_device'))
    return render_template('add_device.html', form=form)


@main.route('/check_history_ont_detail', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.COMMENT)
def check_history_ont_detail():
    form = FindByMacForm()
    field_name = ('mac', 'f', 's', 'p', 'ont_id', 'rx_optical_power', 'temperature', 'voltage',
                  'olt_rx_ont_optical_power', 'last_down_cause', 'last_up_time', 'last_down_time', 'line_profile_id',
                  'line_profile_name', 'server_profile_id', 'server_profile_name', 'create_time',
                  'update_time', 'olt_name', 'machine_room')
    if form.validate_on_submit():
        mac = form.mac.data.upper()
        logger.info('User {} is checking onu {}'.format(session['LOGINNAME'], mac))
        ont_info = ONTDetail.query.filter_by(mac=mac).first()
        if ont_info:
            olt = Device.query.filter_by(id=ont_info.device_id).first()
            data_result = (mac, ont_info.f, ont_info.s, ont_info.p, ont_info.ont_id, ont_info.rx_optical_power,
                           ont_info.temperature, ont_info.voltage, ont_info.olt_rx_ont_optical_power,
                           ont_info.last_down_cause, ont_info.last_up_time, ont_info.last_down_time,
                           ont_info.line_profile_id, ont_info.line_profile_name, ont_info.server_profile_id,
                           ont_info.server_profile_name, ont_info.create_time, ont_info.update_time, olt.device_name,
                           olt.machine_room.name)
            dict_result = dict(zip(field_name, data_result))
            logger.debug(dict_result)
            logger.info('{} history info found'.format(mac))
            session['dict_result'] = dict_result
        else:
            logger.info('onu {} is not found'.format(form.mac.data))
            flash('%s 未找到' % form.mac.data)
        return redirect(url_for('.check_history_ont_detail'))
    result = session.get('dict_result')
    session['dict_result'] = ''
    return render_template('check_history_ont_detail.html', form=form, dict_result=result)


@main.route('/find_by_mac', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.COMMENT)
def find_by_mac():
    form = BaseForm()
    if form.validate_on_submit():
        logger.info('User {} find_by_mac machine room id:{} onu:{}'.
                    format(session['LOGINNAME'], form.machine_room_name.data, form.mac.data))
        mac = form.mac.data.upper()
        machine_room = form.machine_room_name.data
        form.mac.data = ''
        form.machine_room_name.data = ''
        find_result = ont_status(mac, machine_room)
        if find_result['status']:
            session['PRINT'] = find_result['content']
        else:
            flash(find_result['content'])
        return redirect(url_for('.find_by_mac'))
    print_result = session.get('PRINT')
    return render_template('find_by_mac.html', form=form, result=print_result)


@main.route('/check_ont_status', methods=['POST'])
@login_required
@permission_required(Permission.COMMENT)
def check_ont_status():
    mac = request.form.get('mac')
    machine_room = request.form.get('machine_room')
    check_result = ont_status(mac, machine_room, level='callcenter')
    print(check_result)
    return jsonify(json.dumps(check_result, ensure_ascii=False))


@main.route('/manager_register', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.REGION_SUPPORT)
def manager_register():
    """
    ont_register
    :return:  1: success 2: not find ont 3: find ont, but regist fail
    """
    form = OntRegisterFormByManager()
    flash_message = {'1': '光猫注册成功, 请使用\'ONU查询\'功能确认ONU状态',
                     '2': '未发现光猫,请检查线路或联系网管',
                     '3': '发现光猫, 但添加ONT失败,请联系值班网管',
                     '4': '发现光猫并注册, 但是绑定native-vlan失败, 请联系值班网管',
                     '5': 'OLT链接超时, 请联系值班网管',
                     '6': '此光猫已经被注册在其它PON口, 请联系值班网管',
                     '7': '此PON口已达到注册上线,请联系值班网管调整',
                     '104': '发现光猫并注册, 但是绑定native-vlan失败, 系统回滚成功, 请联系值班网管处理',
                     '107': '发现光猫并注册, 但设备native-vlan不存在,系统回滚成功, 请联系值班网管处理',
                     '204': '发现光猫并注册, 但是绑定native-vlan失败, 系统回滚失败, 请联系值班网管处理',
                     '207': '发现光猫并注册, 但设备native-vlan不存在,系统回滚成功, 请联系值班网管处理',
                     '999': '未找到对应机房'}

    if form.validate_on_submit():
        logger.info('User {} is registing an ONU {} in machine room {}, the ONU model is {}, service type is {}'.
                    format(session['LOGINNAME'],
                           form.mac.data,
                           form.machine_room_name.data,
                           form.ont_model_choice.data,
                           form.service_type.data))

        session['MAC'] = form.mac.data.upper()
        session['CUSTOMERNUMBER'] = form.customer_number.data
        session['ONTMODEL'] = form.ont_model_choice.data
        service_type = form.service_type.data

        device_list = get_device_info(form.machine_room_name.data)

        data = Log(operator=session.get('LOGINUSER'), machine_room_id=form.machine_room_name.data, mac=form.mac.data,
                   customer_number=form.customer_number.data, type=3, create_time=time.localtime())

        if device_list:
            for device in device_list:
                args = {'reporter_name': session.get('LOGINNAME'),
                        'reporter_group': User.query.filter_by(email=session['LOGINUSER']).first().area,
                        'register_name': session.get('LOGINNAME'),
                        'remarks': 'BY SNOC',
                        'username': form.customer_number.data,
                        'user_addr': form.customer_distinct.data,
                        'mac': session.get('MAC'),
                        'ip': device.ip,
                        'login_name': device.login_name,
                        'login_password': device.login_password,
                        'ont_model': session.get('ONTMODEL'),
                        'device_id': device.id,
                        'status': 1,
                        'service_type': service_type
                        }

                logger.info('regist on device {}'.format(device))
                for key, value in args.items():
                    logger.debug('{}: {}'.format(key, value))

                # start to register ont
                session['REGIST_RESULT'] = ont_register_func(**args)
                if session['REGIST_RESULT'] == 1:
                    logger.info('regist {} on machine room {} successful'.
                                format(form.mac.data, form.machine_room_name.data))
                    break
                if session['REGIST_RESULT'] == 6:
                    logger.info('register {} on machine room {} fail, cause the ONT is already exist'
                                .format(form.mac.data, form.machine_room_name.data))
                    break
        else:
            session['REGIST_RESULT'] = 999

        logger.debug("regist result is: {} ".format(session.get('REGIST_RESULT')))
        flash(flash_message[str(session['REGIST_RESULT'])])

        form.mac.data = ''
        form.machine_room_name.data = ''
        add_log(data=data)
        session['REGIST_RESULT'] = ''
        return redirect(url_for('.index'))
    return render_template('manager_register.html', form=form)


@main.route('/user_register', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def user_register():
    form = RegistrationForm()
    if form.validate_on_submit():
        logger.info('User {} is registering a new user:{}, email:{}, phoneNum: {}, role_id:{}, area:{}, duty:{}'.
                    format(session['LOGINNAME'],
                           form.username.data,
                           form.email.data,
                           form.phoneNum.data,
                           form.role.data,
                           form.area.data,
                           form.duty.data))
        machine_room_list = form.machine_room_name.data
        permit_machineroom = 0
        for mr in machine_room_list:
            permit_value = MachineRoom.query.filter_by(id=mr).first()
            if permit_value:
                permit_machineroom |= int(permit_value.permit_value, 16)

        logger.info('This new user {} permitted on machine room {}'.
                    format(form.username.data, hex(permit_machineroom)))

        try:
            user_role = Role.query.filter_by(id=form.role.data).first()
            user = User(username=form.username.data,
                        email=form.email.data,
                        phoneNum=form.phoneNum.data,
                        password=form.password.data,
                        role=user_role,
                        area=form.area.data,
                        duty=form.duty.data,
                        permit_machine_room=hex(permit_machineroom),
                        status=1,
                        workorder_login_name=form.workorder_login_name.data)

            db.session.add(user)
            db.session.commit()
            logger.info('User {} register success'.format(form.username.data))
            flash('用户添加成功')
        except Exception as e:
            logger.error('user register {} fail for {}'.format(form.username.data, e))
            db.session.rollback()
            flash('用户添加失败, 请联系网管')
        return redirect(url_for('.user_register'))
    return render_template('user_register.html', form=form)


@main.route('/ont_register_inspector', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.COMMENT)
def ont_register_inspector():
    form = OntRegisterInspector()
    if form.validate_on_submit():
        start_time = form.start_time.data
        stop_time = form.stop_time.data
        machine_room_name = '_'.join(form.machine_room_name.data)
        area = '_'.join(form.area.data)
        # 尝试支持任何格式的MAC输入，只要是输入12位字符
        mac = form.mac.data.upper()
        b = re.findall(r'(\w{2})', mac)
        mac = '-'.join([''.join(b[n:n+2]) for n in [0, 2, 4]]).upper()
        customer_number = form.customer_number.data
        customer_addr = form.customer_addr.data
        ont_model_choice = '_'.join(form.ont_model_choice.data)
        fsp = form.fsp.data
        cevlan = form.cevlan.data

        # write log
        logger.info('User {} inspect the register info'.format(session['LOGINNAME']))
        logger.debug('\tstart time: {}\n'
                     '\tstop time: {}\n'
                     '\tmachine room: {}\n'
                     '\tarea: {}\n'
                     '\tmac:{}\n'
                     '\tcustomer number: {}\n'
                     '\tcustomer addr: {}\n'
                     '\tont model: {}\n'
                     '\tfsp: {}\n'
                     '\tcevlan: {}'.
                     format(start_time, stop_time, machine_room_name, area, mac, customer_number, customer_addr,
                            ont_model_choice, fsp, cevlan))

        return redirect(url_for('.ont_register_inspector_list', start_time=start_time, stop_time=stop_time,
                                machine_room_name=machine_room_name, mac=mac, area=area, fsp=fsp, cevlan=cevlan,
                                customer_number=customer_number, ont_model_choice=ont_model_choice,
                                customer_addr=customer_addr))
    return render_template('ont_register_inspector.html', form=form)


@main.route('/ont_register_inspector_list', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.COMMENT)
def ont_register_inspector_list():
    page = request.args.get('page', 1, type=int)
    start_time = request.args.get('start_time', '2000-01-01 00:00:00')
    stop_time = request.args.get('stop_time', '2099-01-01 00:00:00')
    machine_room_name = request.args.get('machine_room_name').split('_') or '%'
    mac = request.args.get('mac').strip() or '%'
    area_select = request.args.get('area').split('_') or '%'
    customer_number = request.args.get('customer_number').strip() or '%'
    customer_addr = request.args.get('customer_addr') or '%'
    ont_model_choice = request.args.get('ont_model_choice').split('_') or '%'
    fsp = request.args.get('fsp') or '%'
    cevlan = request.args.get('cevlan') or '%'
    status = 1

    if fsp == '%':
        f = s = p = '%'
    else:
        f, s, p = fsp.split('/')

    if not machine_room_name[0]:
        if session.get('permit_machine_room') == '0xffffffffff':
            machine_room_name[0] = '%'
        else:
            machine_room_name = [i[0] for i in get_machine_room_by_area(session.get('permit_machine_room'))]
    if not area_select[0]:
        if Area.query.filter_by(id=session['LOGINAREA']).first().area_machine_room == '0xffffffffff':
            area_select[0] = '%'
        else:
            area_select[0] = str(session.get('LOGINAREA'))
    if not ont_model_choice[0]:
        ont_model_choice[0] = '%'

    if customer_addr != '%':
        customer_addr = '%' + customer_addr + '%'

    logger.debug('transfer params: {} {} {} {} {} {} {} {} {} {} {}'.
                 format(page, start_time, stop_time, machine_room_name, mac, area_select, customer_number,
                        customer_addr,
                        ont_model_choice, fsp, cevlan))

    POSTS_PER_PAGE = 10

    logger.info('begin to combin sql.')
    machineroom_sql = or_(*[Device.machine_room_id.like(mr_id) for mr_id in machine_room_name])
    dev_sql = or_(*[OntRegister.device_id.like(device.id)
                    for device in Device.query.filter(machineroom_sql).all()])
    area_sql = or_(*[OntRegister.reporter_group.like(group) for group in area_select])
    ontmodel_sql = or_(*[OntRegister.ont_model.like(ont_model) for ont_model in ont_model_choice])

    if page < 1:
        page = 1

    paginate = OntRegister.query.filter(dev_sql, area_sql, ontmodel_sql,
                                        OntRegister.create_time.between(start_time, stop_time),
                                        OntRegister.mac.like(mac),
                                        OntRegister.username.like(customer_number), OntRegister.status.__eq__(status),
                                        OntRegister.f.like(f), OntRegister.s.like(s), OntRegister.p.like(p),
                                        OntRegister.cevlan.like(cevlan), OntRegister.user_addr.like(customer_addr)). \
        order_by(desc(OntRegister.create_time)).paginate(page, POSTS_PER_PAGE, False)

    logger.info(str(paginate))

    # get the device and machine room dict
    device_info = Device.query.all()
    device_machine = {}
    device = {}
    for d in device_info:
        device[d.id] = d.device_name
        device_machine[d.id] = d.machine_room.name

    object_list = paginate.items

    kwargs = {'start_time': start_time,
              'stop_time': stop_time,
              'machine_room_name': '_'.join(machine_room_name),
              'mac': mac,
              'area_select': '_'.join(area_select),
              'customer_number': customer_number,
              'ont_model_choice': '_'.join(ont_model_choice),
              'fsp': fsp,
              'cevlan': cevlan,
              'customer_addr': customer_addr}

    area = {str(a.id): a.area_name for a in Area.query.all()}

    return render_template('ont_register_inspector_list.html',
                           pagination=paginate,
                           object_list=object_list,
                           area=area,
                           device_machine=device_machine,
                           device=device,
                           POSTS_PER_PAGE=POSTS_PER_PAGE,
                           **kwargs)


@main.route('/local_user_check', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.FOLLOW)
def local_user_check():
    if request.method == 'GET':
        modal_form = UserModal()
        return render_template('local_user_check.html', modal_form=modal_form)
    elif request.method == 'POST':
        print('post local user check')
        username = '%' + request.form.get('username', '%') + '%'
        mail = '%' + request.form.get('mail', '%') + '%'
        print(username, mail)
        draw = request.form.get('draw')
        page_start = int(request.form.get('start', '0'))
        page_end = page_start + int(request.form.get('length'))
        roles_name = {r.id: r.name for r in Role.query.all()}
        area_name = {a.id: a.area_name for a in Area.query.all()}

        if request.form.get('username') or request.form.get('mail'):
            if Role.query.filter_by(id=session['ROLE']).first().permissions >= 127:
                user_list = User.query.filter(User.status.__eq__(1),
                                              User.username.like(username),
                                              User.email.like(mail)).order_by(User.id).all()
            else:
                user_list = User.query.filter(User.status.__eq__(1),
                                              User.username.like(username),
                                              User.email.like(mail),
                                              User.username.__eq__(session['LOGINNAME'])).order_by(User.id).all()
            print(user_list)
            data = [[u.id,
                     u.email,
                     u.username,
                     area_name[u.area],
                     roles_name[u.role_id],
                     """<a data-toggle="modal" data-target="#update" onclick="editInfo(""" + str(u.id) + """)">
                     <img src="../static/edit.png" alt="" title="" border="0"/></a>""",
                     """<img onclick="delete_user(""" + str(u.id) + """)"
                     src="../static/trash.png" alt="" title=""
                     border="0"/>"""]
                    for u in user_list]
        else:
            if Role.query.filter_by(id=session['ROLE']).first().permissions >= 127:
                user_list = User.query.filter(User.status.__eq__(1)).order_by(User.id).all()
            else:
                user_list = User.query.filter_by(status=1, username=session['LOGINNAME']).order_by(User.id).all()
            print(user_list)
            for u in user_list:
                print(u.id, u.email, u.username, u.area, u.id)
            data = [[u.id,
                     u.email,
                     u.username,
                     area_name.get(u.area),
                     roles_name.get(u.role_id),
                     """<a data-toggle="modal" data-target="#update" onclick="editInfo(""" + str(u.id) + """)">
                     <img src="../static/edit.png" alt="" title="" border="0"/></a>""",
                     """<img onclick="delete_user(""" + str(u.id) + """)"
                     src="../static/trash.png" alt="" title=""
                     border="0"/>"""]
                    for u in user_list]

        logger.info('User {} is checking user list'.format(session['LOGINNAME']))

        rest = {'draw': int(draw),
                'recordsTotal': len(data),
                'recordsFiltered': len(data),
                'data': data[page_start:page_end]
                }
        print(rest)

        return jsonify(rest)


@main.route('/release_ont', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.MAN_ON_DUTY)
def release_ont():
    """
    status = {1: '新注册', 2: '解除绑定'}
    :return:
    """
    mac = request.args.get('mac')
    delete_mac = request.args.get('delete_mac')
    device_id = request.args.get('device_id')
    f = request.args.get('f')
    s = request.args.get('s')
    p = request.args.get('p')
    ont_id = request.args.get('ont_id')
    start_time = request.args.get('start_time')
    stop_time = request.args.get('stop_time')
    machine_room_name = request.args.get('machine_room_name')
    area = request.args.get('area')
    customer_number = request.args.get('customer_number')
    ont_model_choice = request.args.get('ont_model_choice')

    # write log
    logger.info('User {} of area {} is releasing ont {} on device {} {}/{}/{} - {}'.
                format(session['LOGINNAME'], session['LOGINAREA'], delete_mac, device_id, f, s, p, ont_id))

    if release_ont_func(device_id, f, s, p, ont_id, delete_mac):
        logger.info('ONT {} is released by {}'.format(delete_mac, session['LOGINNAME']))
        flash('ONU解绑成功')

    kwargs = {'start_time': start_time,
              'stop_time': stop_time,
              'machine_room_name': machine_room_name,
              'mac': mac,
              'area': area,
              'customer_number': customer_number,
              'ont_model_choice': ont_model_choice}
    return redirect(url_for('.ont_register_inspector_list', page=1, **kwargs))


@main.route('/maintain_pevlan', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def maintain_pevlan():
    form = MaintainPevlanForm()
    if form.validate_on_submit():
        logger.info('User {} is maintaining_pevlan on device:{}, pevlan:{}, service tyep:{}'
                    .format(session['LOGINNAME'], form.device_name.data, form.pevlan.data, form.service_type.data))
        try:
            now_pevlan_info = PeVlan.query.filter_by(device_id=form.device_name.data,
                                                     pevlan=form.pevlan.data).first()
            logger.info('pevlan {}\'s service type is changing from {} to {}'.format(form.pevlan.data,
                                                                                     now_pevlan_info.service_type,
                                                                                     form.service_type.data))
            flash('pevlan {}\'s service type is changing from {} to {}'.format(form.pevlan.data,
                                                                               now_pevlan_info.service_type,
                                                                               form.service_type.data))
            if now_pevlan_info:
                now_pevlan_info.service_type = form.service_type.data

                db.session.add(now_pevlan_info)
            else:
                # write log
                logger.info('pevlan is not existed in this device, {} {} is insert into db'
                            .format(form.pevlan.data, form.service_type.data))

                # flash message to user
                flash('pevlan is not existed in this device, {} {} is insert into db'.
                      format(form.pevlan.data, form.service_type.data))

                new_pevlan_info = PeVlan(device_id=form.device_name.data,
                                         pevlan=form.pevlan.data,
                                         service_type=form.service_type.data)
                db.session.add(new_pevlan_info)
            db.session.commit()
            logger.info('maintain pevlan successful')
            flash('维护成功')
        except Exception as e:
            logger.error(e)
            # 但是此处不能捕获异常
            flash('维护失败')
        return redirect(url_for('.maintain_pevlan'))
    return render_template('maintain_pevlan.html', form=form)


@main.route('/manual_sync', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def manual_sync():
    form = ManualSync()
    if form.validate_on_submit():
        # write log
        logger.info('User {} manual sync: {} {}'
                    .format(session['LOGINNAME'], form.device_name.data, form.sync_action.data))
        sync_result = manual_sync_func(func_id=form.sync_action.data, device_id_list=form.device_name.data)
        if sync_result:
            logger.info('sync finished')
            flash('同步已完成')
        else:
            logger.warning('sync fail')
            flash('同步失败')
        return redirect(url_for('.manual_sync'))
    return render_template('manual_sync.html', form=form)


@main.route('/area_config', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def area_config():
    logger.info('User {} is checking area list'.format(session['LOGINNAME']))
    page = request.args.get('page', 1, type=int)
    update_result = request.args.get('update_result')
    flash_message = {1: '大区信息修改成功', 2: '大区信息修改失败', 3: '无权修改大区信息', 4: '未修改信息'}

    if update_result:
        session['update_result'] = update_result

    if session.get('update_result') and not update_result:
        flash(flash_message[int(session['update_result'])])
        session['update_result'] = ''
    form = AreaConfigForm()
    modal_form = AreaModal()

    if form.validate_on_submit():
        logger.info('User {} is configuring the machine room included in area {}'
                    .format(session['LOGINNAME'], form.area_machine_room.data, form.area_name.data))

        machine_room_list = form.area_machine_room.data
        permit_machineroom = 0
        area_desc_list = []
        for mr in machine_room_list:
            permit_value = MachineRoom.query.filter_by(id=mr).first()
            area_desc_list.append(permit_value.name)
            if permit_value:
                permit_machineroom |= int(permit_value.permit_value, 16)

        area_desc = ','.join(area_desc_list)
        logger.info('The hex of the permitted machine room is {}'.format(permit_machineroom))
        try:
            insert_area = Area(area_name=form.area_name.data,
                               area_desc=area_desc,
                               area_machine_room=hex(permit_machineroom))
            db.session.add(insert_area)
            db.session.commit()
            logger.info('Area config successful')
            flash('大区添加成功')
        except Exception as e:
            logger.error('config area fail for {}'.format(e))
            flash('插入数据失败')
        return redirect(url_for('.area_config'))

    POSTS_PER_PAGE = 10

    if page < 1:
        page = 1
    paginate = Area.query.order_by(Area.id).paginate(page, POSTS_PER_PAGE, False)

    object_list = paginate.items

    return render_template('area_config.html',
                           pagination=paginate,
                           object_list=object_list,
                           POSTS_PER_PAGE=POSTS_PER_PAGE,
                           form=form,
                           modal_form=modal_form)


@main.route('/community_machineroom_config', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def community_machineroom_config():
    logger.info('User {} is checking community_machineroom list'.format(session['LOGINNAME']))
    page = request.args.get('page', 1, type=int)

    form = CommuntiyMachineroomConfig()

    if form.validate_on_submit():
        logger.info('User {} is configuring the machine room included in area {}'
                    .format(session['LOGINNAME'], form.machine_room.data, form.community_name.data))

        machine_room_list = form.machine_room.data
        community_name = form.community_name.data
        try:
            for mr in machine_room_list:
                mr_name = MachineRoom.query.filter_by(id=mr).first().name
                if Community.query.filter_by(community_name=community_name, machine_room_id=mr).all():
                    flash('{} 对应 {} 已经存在'.format(community_name, mr_name))
                else:
                    add_data = Community(community_name=community_name, machine_room_id=mr)
                    db.session.add(add_data)
                    db.session.commit()
                    flash('{} 对应 {} 添加成功'.format(community_name, mr_name))
        except Exception as e:
            logger.error(e)
            db.session.rollback()
            flash('添加失败')

        return redirect(url_for('.community_machineroom_config'))

    POSTS_PER_PAGE = 20

    if page < 1:
        page = 1
    paginate = Community.query.order_by(Community.community_name).paginate(page, POSTS_PER_PAGE, False)

    object_list = paginate.items

    machineroom = {m.id: m.name for m in MachineRoom.query.all()}

    return render_template('community_machineroom_config.html',
                           pagination=paginate,
                           object_list=object_list,
                           POSTS_PER_PAGE=POSTS_PER_PAGE,
                           form=form,
                           machine_room=machineroom)


@main.route('/community_delete', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def community_delete():
    community_id = request.args.get('community_id')
    print(community_id)
    community_tobe_deleted = Community.query.filter_by(id=community_id).first()
    logger.debug('User {} is deleting community {} to machine room {}'.format(session['LOGINNAME'],
                                                                              community_tobe_deleted.community_name,
                                                                              community_tobe_deleted.machine_room_id))

    try:
        db.session.delete(community_tobe_deleted)
        db.session.commit()
        logger.info('community is deleted')
        flash('社区对应关系删除成功')
    except Exception as e:
        logger.error('Delete user fail:{}'.format(e))
        flash('社区对应关系删除失败')

    return redirect(url_for('.community_machineroom_config'))


@main.route('/ont_autofind', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.COMMENT)
def ont_autofind():
    form = OntAutoFindForm()
    print_result = defaultdict(list)
    if form.validate_on_submit():
        machine_room = form.machine_room.data
        # write log
        logger.info('User {} is using auto find function on machine room {}'
                    .format(session['LOGINNAME'], machine_room))

        ont_autofind_result = ont_autofind_func(machine_room)

        if ont_autofind_result:
            for key, value in ont_autofind_result.items():
                result = []
                for line in value:
                    if not re.search(r'display|config', line):
                        logger.debug('filtered line: {}'.format(line))
                        result.append(line)
                print_result[key] = result

            session['ONTAUTOFIND'] = print_result
            form.machine_room.data = ''
            return redirect(url_for('.ont_autofind'))
        else:
            flash('OLT连接超时, 或者此机房无对应设备')
    print_ = session.get('ONTAUTOFIND')
    session['ONTAUTOFIND'] = ''
    return render_template('ont_autofind.html', form=form, result=print_)


@main.route('/olt_temp', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.COMMENT)
def olt_temp():
    form = OltCheck()
    print_result = defaultdict(list)
    if form.validate_on_submit():
        machine_room = form.machine_room.data
        logger.info('User {} is using olt_temp on machine room {}'.format(session['LOGINNAME'], machine_room))

        olt_temp_result = olt_temp_func(machine_room)

        if olt_temp_result:
            for key, value in olt_temp_result.items():
                result = []
                for line in value:
                    if not re.search(r'display|config', line):
                        logger.debug('filtered line: {}'.format(line))
                        result.append(line)
                print_result[key] = result

            session['OLTTEMP'] = print_result
            form.machine_room.data = ''
            return redirect(url_for('.olt_temp'))
        else:
            flash('OLT连接超时,请重试或联系网管')
    print_ = session.get('OLTTEMP')
    session['OLTTEMP'] = ''
    return render_template('olt_temp.html', form=form, result=print_)


@main.route('/userinfo_update', methods=['POST'])
@login_required
@permission_required(Permission.FOLLOW)
def userinfo_update():
    params = request.get_data()
    print(params)
    jl = params.decode('utf-8')
    jd = json.loads(jl)
    password = jd.get('pass')
    username = jd.get('username')
    area = jd.get('area')
    role = jd.get('role')
    duty = jd.get('duty')
    id = jd.get('id')
    workorder = jd.get('workorder')

    print('password: ', password, ' username: ', username, ' area: ', area, ' role: ', role, ' duty: ', duty, ' id: ',
          id, ' workorder: ', workorder)

    logger.info('User {} is update {}\'s info'.format(session['LOGINNAME'], id))
    logger.debug(password)
    if id == str(session.get('SELFID')) or Role.query.filter_by(id=session['ROLE']).first().permissions >= 127:
        userinfo_tobe_changed = User.query.filter_by(id=id).first()

        if password:
            userinfo_tobe_changed.password = password
        if username:
            userinfo_tobe_changed.username = username
        if area:
            userinfo_tobe_changed.area = area
        if role:
            userinfo_tobe_changed.role_id = role
        if duty:
            userinfo_tobe_changed.duty = duty
        if workorder:
            userinfo_tobe_changed.workorder_login_name = workorder

        if password or username or area or role or duty or workorder:
            try:
                db.session.add(userinfo_tobe_changed)
                db.session.commit()
                update_result = 1
                logger.info('Userinfo of user id {} is changed'.format(id))
            except Exception as e:
                update_result = 2
                db.session.rollback()
                logger.error('Userinfo change fail: {}'.format(e))
        else:
            update_result = 4
    else:
        logger.info('This user do not permitted to alter user info')
        update_result = 3

    return jsonify({'status': update_result})


@main.route('/user_delete', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.FOLLOW)
def user_delete():
    params = request.get_data()
    print(params)
    jl = params.decode('utf-8')
    jd = json.loads(jl)
    user_id = jd['id']
    print(user_id)
    user_tobe_deleted = User.query.filter_by(id=user_id).first()
    logger.debug('User {} is deleting user {}'.format(session['LOGINNAME'], user_tobe_deleted.username))
    if user_tobe_deleted.email == session['LOGINUSER']:
        status = 1
    else:
        if Role.query.filter_by(id=session['ROLE']).first().permissions < Role.query.filter_by(
                name='SNOC').first().permissions:
            logger.debug(session['ROLE'])
            status = 2
        else:
            logger.info('try to delete {}:{}:{}'
                        .format(user_tobe_deleted.id, user_tobe_deleted.username, user_tobe_deleted.email))
            try:
                # 9 means deleted
                # user_tobe_deleted.status = 9
                db.session.delete(user_tobe_deleted)
                db.session.commit()
                logger.info('user is deleted')
                status = 3
            except Exception as e:
                logger.error('Delete user fail:{}'.format(e))
                status = 4

    return jsonify({'status': status})


@main.route('/areainfo_update', methods=['GET', 'POST'])
def areainfo_update():
    area_id = request.form.get('area_id')
    area_name = request.form.get('area_name')
    area_desc_list = []
    area_machine_room = request.form.get('machine_room_name')
    logger.debug('area_name {} machine_room {}'.format(area_name, area_machine_room))
    if area_machine_room != 'null':
        area_machine_room = area_machine_room.split(',')
    logger.debug(area_machine_room)

    areainfo_tobe_updated = Area.query.filter_by(id=area_id).first()

    if areainfo_tobe_updated.area_machine_room == '0xffffffffff':
        return redirect(url_for('.area_config', update_result=3))

    if area_name:
        areainfo_tobe_updated.area_name = area_name

    if area_machine_room != 'null':
        logger.debug('area_machine_room {}'.format(area_machine_room))
        permit_machineroom = 0
        for mr in area_machine_room:
            permit_value = MachineRoom.query.filter_by(id=mr).first()
            area_desc_list.append(permit_value.name)
            if permit_value:
                permit_machineroom |= int(permit_value.permit_value, 16)

        areainfo_tobe_updated.area_machine_room = hex(permit_machineroom)

        logger.info('The hex of the permitted machine room is {}'.format(hex(permit_machineroom)))

        area_desc = ','.join(area_desc_list)
        areainfo_tobe_updated.area_desc = area_desc

    if area_name or area_machine_room:
        try:
            db.session.add(areainfo_tobe_updated)
            db.session.commit()
            logger.info('update area info successful')
            update_result = 1
        except Exception as e:
            logger.error(e)
            update_result = 2
    else:
        update_result = 4

    return redirect(url_for('.area_config', update_result=update_result))


@main.route('/gps_location', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.FOLLOW)
def gps_location():
    return render_template('GPS.html')


@main.route('/alter_epon_interface', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.FOLLOW)
def alter_epon_interface():
    flash_alter_info = {True: '原机房端口(源端口)注册的ONU出现在不同的目标端口上, 平台仅支持迁移匹配到的ONU.',
                        False: '可选择整个源端口迁移到目的端口, 也可选择仅迁移匹配到的ONU',
                        'no autofind': '没有在目标机房找到上线的ONU',
                        'the destination fsp eq source fsp': 'the destination fsp eq source fsp',
                        'not find ont info in dst machine room': 'not find ont info in dst machine room'}

    machine_room = dict(get_machine_room_by_area(session.get('permit_machine_room')))
    print(machine_room)
    print('start to alter epon interface')
    form = AlterEponInterfaceForm()
    if form.validate_on_submit():
        discover_result = \
            discover_alter_interface_func(form.source_machine_room.data, form.destincation_machine_room.data)

        # t = threading.Thread(target=discover_alter_interface_func,
        #                      args=(form.source_machine_room.data, form.destincation_machine_room.data)).start()

        if isinstance(discover_result, list):
            [session['altert_matched_onu_flag'],
             session['fsp_delete_target'],
             session['all_ont_tobe_deleted'],
             session['ont_delete_list']] = discover_result

            flash(flash_alter_info[session['altert_matched_onu_flag']])

            return redirect(url_for('.alter_epon_interface'))
        else:
            flash(flash_alter_info[discover_result])
    a = session.get('fsp_delete_target')
    b = session.get('all_ont_tobe_deleted')
    c = session.get('ont_delete_list')
    d = session.get('altert_matched_onu_flag')
    session['fsp_delete_target'] = ''
    session['all_ont_tobe_deleted'] = ''
    session['ont_delete_list'] = ''

    return render_template('alter_epon.html', form=form, fsp_delete_target=a,
                           all_ont_tobe_deleted=b,
                           ont_delete_list=c,
                           altert_matched_onu_flag=d,
                           machine_room=machine_room)


@main.route('/do_alter_int', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.FOLLOW)
def gps():
    all_ont_tobe_deleted = request.args.getlist('all_ont_tobe_deleted')
    ont_delete_list = request.args.getlist('ont_delete_list')
    if all_ont_tobe_deleted:
        for ont_info in all_ont_tobe_deleted:
            ont_info = ont_info.replace('None', "'None'").replace('\'', '\"').replace('(', '[').replace(')', ']')
            ont_info = json.loads(ont_info)
            for mac, alter_detail in ont_info.items():
                print('alter {} from {} to {}, using {}'
                      .format(mac,
                              alter_detail['src_dst'][0],
                              alter_detail['src_dst'][1],
                              alter_detail['ont_info']))

    logger.debug('checkbox {}  {}'.format(all_ont_tobe_deleted, ont_delete_list))
    return redirect(url_for('.alter_epon_interface'))


@main.route('/licence_control', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def licence_control():
    expire_date, expire_in, pubkey = get_pubkey()
    expire_date = time.strftime('%Y-%m-%d', time.localtime(expire_date))
    pubkey = pubkey.replace('\n', '\r\n')
    return render_template('licence_control.html',
                           expire_date=expire_date,
                           expire_in=expire_in,
                           pubkey=pubkey)


@main.route('/update_licence', methods=['POST'])
@login_required
@permission_required(Permission.ADMINISTER)
def update_licence():
    if update_crypted_licence(request.form.get('new_licence')):
        return jsonify(json.dumps({'status': 'OK'}))
    else:
        return jsonify(json.dumps({'status': 'FAIL'}))


@main.route('/get_ontinfo', methods=['POST'])
def get_ontinfo():
    """
    用于获取工单平台数据
    :return:
    """
    if request.remote_addr == '127.0.0.1':
        try:
            ont_verbose_info = []
            f, s, p = request.json['fsp']
            ip = request.json['device_ip']

            device_id = Device.query.filter_by(ip=ip).first()

            if device_id:
                # 如果ontid_list 传递的是all，那么查找对应接口下所有ontid的信息
                if request.json['ontid_list'] == 'all':
                    ontid_list = [org.ont_id for org in
                                  OntRegister.query.filter_by(device_id=Device.query.filter_by(ip=ip).first().id,
                                                              f=f, s=s, p=p).all()]
                else:
                    ontid_list = request.json['ontid_list']

                try:
                    loginName = User.query.filter_by(email=session['LOGINUSER']).first().workorder_login_name
                except:
                    loginName = defaultLoginName

                if loginName:
                    for ontid in ontid_list:
                        ont_info = OntRegister.query.filter_by(device_id=Device.query.filter_by(ip=ip).first().id,
                                                               f=f, s=s, p=p, ont_id=ontid).first()
                        if ont_info:
                            ont_verbose_info.append(customerInfoQueryAction(ont_info.username, loginName))
                        else:
                            logger.debug('No user found for ontid {}'.format(ontid))
                    return jsonify({'status': 'OK', 'content': ont_verbose_info})
                else:
                    # 这个判断目前不起作用，因为前面代码写了try，如果不存在会产生一个默认的工单账户来获取accountId
                    return jsonify({'status': 'Fail', 'content': '未注册工单平台账户'})
            else:
                return jsonify({'status': 'Fail', 'content': '设备未找到'})
        except:
            return jsonify({'status': 'Fail', 'content': '输入参数错误'})
    else:
        return jsonify({'status': 'Fail', 'content': '不允许访问'})

