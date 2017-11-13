from flask import redirect, session, url_for, render_template, flash, request, jsonify
from flask_login import login_required
from ..models import Device, ONTDetail, Log, MachineRoom, Permission, User, OntRegister, PeVlan, Area, Role, \
    ontinfo_translate, Community, defaultLoginName
from ..decorators import admin_required, permission_required
from ..my_func import FindLOID, add_log, FindByMac, ont_register_func, release_ont_func, manual_sync_func, \
    get_machine_room_by_area, ont_autofind_func, olt_temp_func, discover_alter_interface_func
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


@main.route('/handwork', methods=['GET'])
@login_required
@permission_required(Permission.COMMENT)
def handwork():
    if request.method == 'GET':
        session['index'] = 'from_index_file'
        return render_template('handwork.html')


@main.route('/ont_register_for_handwork', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.COMMENT)
def ont_register_for_handwork():
    """
    ont_register
    :return:  1: success 2: not find ont 3: find ont, but regist fail
    """

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
    account_id = request.args.get('account_id', '1')

    loginName = User.query.filter_by(email=session['LOGINUSER']).first().workorder_login_name
    print(account_id)

    js = customerInfoQueryAction(account_id, loginName)

    if len(js['customerListInfo']['customerList']) > 0:
        customer_info = js['customerListInfo']['customerList'][0]
        machine_room_community = Community.query.filter_by(community_name=customer_info['communityName']).all()
        machine_room_list = []
        permitted_machine_room = get_machine_room_by_area(session.get('permit_machine_room'))
        print(permitted_machine_room)
        pmid = [mid[0] for mid, mname in permitted_machine_room]
        print(pmid)
        for cm in machine_room_community:
            machineroom_info = MachineRoom.query.filter_by(id=cm.machine_room_id).first()
            if str(machineroom_info.id) in pmid:
                machine_room_list.append([machineroom_info.id, machineroom_info.name])
        if len(machine_room_list) > 0:
            form = OntRegisterForm(machine_room_list)
            print(customer_info)
        else:
            flash('无对应上联机房')
            return render_template('index.html')
    else:
        print('no customer info return')
        return render_template('index.html')

    if form.validate_on_submit():
        logger.info('User {} is handwork input an ONU {} in machine room {}, the ONU model is {}, service type is {}'.
                    format(session['LOGINNAME'],
                           form.mac.data,
                           form.machine_room_name.data,
                           form.ont_model_choice.data,
                           form.service_type.data))

        session['MAC'] = form.mac.data.upper()
        session['CUSTOMERNUMBER'] = customer_info.get('accountId')
        session['ONTMODEL'] = form.ont_model_choice.data
        service_type = form.service_type.data

        fsp, ont_id, result, _ = ont_status(form.mac.data.upper(), form.machine_room_name.data)

        if fsp:
            pass

        device_list = get_device_info(form.machine_room_name.data)

        if device_list:
            for device in device_list:
                args = {'reporter_name': session.get('LOGINNAME'),
                        'reporter_group': User.query.filter_by(email=session.get('LOGINUSER')).first().area,
                        'register_name': session.get('LOGINNAME'),
                        'remarks': '',
                        'username': customer_info.get('accountId'),
                        'user_addr': customer_info.get('communityName') + '/' + customer_info.get('aptNo'),
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

                # ont register
                session['REGIST_RESULT'] = ont_register_func(**args)

                if session['REGIST_RESULT'] == 1:
                    logger.info('register {} on machine room {} successful'.
                                format(form.mac.data, form.machine_room_name.data))
                    break
                if session['REGIST_RESULT'] == 6:
                    logger.info('register {} on machine room {} fail'
                                .format(form.mac.data, form.machine_room_name.data))
                    break
        else:
            session['REGIST_RESULT'] = 999

        logger.debug("regist result is: {} ".format(session.get('REGIST_RESULT')))
        flash(flash_message[str(session['REGIST_RESULT'])])

        form.mac.data = ''
        form.machine_room_name.data = ''
        session['REGIST_RESULT'] = ''
        return redirect(url_for('.ont_register_from_accountid'))
    if session.get('index') == 'from_index_file':
        return render_template('ont_register_for_handwork.html',
                               form=form,
                               js=customer_info)
    else:
        return render_template('handwork.html')
