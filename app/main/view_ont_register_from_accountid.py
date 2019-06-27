from flask import redirect, session, url_for, render_template, flash, request, jsonify
from flask_login import login_required
from ..models import *
from ..decorators import admin_required, permission_required
from ..my_func import *
from .forms import *
from . import main
import time
import json
from ..MyModule.GetWorkorderInfo import customerInfoQueryAction
from ..MyModule.OntStatus import ontLocation
from .. import db, logger


@main.route('/', methods=['GET'])
@login_required
@permission_required(Permission.COMMENT)
def index():
    if session.get('REGIST_RESULT') is not None:
        flash(session['REGIST_RESULT'])
        session['REGIST_RESULT'] = None
    session['index'] = 'from_index_file'
    return render_template('index.html')


@main.route('/account_search', methods=['POST'])
@login_required
@permission_required(Permission.COMMENT)
def account_search():
    account_id = request.form.get('account_id')
    loginName = User.query.filter_by(email=session.get('LOGINUSER')).first().workorder_login_name
    print(loginName)
    if not loginName:
        print('no loginname')
        return jsonify(json.dumps({'status': '未注册工单平台，请联系管理员'}))
    js = customerInfoQueryAction(account_id, loginName)
    print(js)
    if len(js['customerListInfo']['customerList']) > 0:
        if js['customerListInfo']['customerList'][0]['currentState'] in ['1', '2', '4']:
            return jsonify(json.dumps({'status': 'OK'}))
        else:
            # return jsonify(json.dumps({'status': 'OK'}))
            return jsonify(json.dumps({'status': '此用户编号当前状态非"开通、试用、开户",不可注册'}))
    else:
        # return jsonify(json.dumps({'status': '用户信息查询失败 请确认工单平台账号设置正确  请确认已开户'}))
        return jsonify(json.dumps({'status': 'CUCC'}))


@main.route('/regist_precheck', methods=['POST'])
@login_required
@permission_required(Permission.COMMENT)
def regist_precheck():
    """
    record_flag = {'1': 'modify onu', '2': 'alternate pon', '3': 'other', '4': 'new register'}
    :return:
    """

    k = {'account_id': request.form.get('account_id'),
         'mac': request.form.get('mac').upper(),
         'machine_room_id': request.form.get('machine_room_id'),
         'currentState': request.form.get('currentState'),
         'customerAddr': request.form.get('communityName') + '/' + request.form.get('aptNo'),
         'communityName': request.form.get('communityName'),
         'aptNo': request.form.get('aptNo'),
         'ont_model_choice': request.form.get('ont_model_choice'),
         'service_type': request.form.get('service_type'),
         'service_type_dict': {'1': 'founderbn', '4': 'unicom'}}

    return ont_register(**k)


@main.route('/ont_register_from_accountid', methods=['GET', 'POST'])
@login_required
@permission_required(Permission.COMMENT)
def ont_register_from_accountid():
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

    loginName = User.query.filter_by(email=session.get('LOGINUSER')).first().workorder_login_name
    logger.debug('用户编号：{}'.format(account_id))

    js = customerInfoQueryAction(account_id, loginName)

    if len(js['customerListInfo']['customerList']) > 0:
        customer_info = js['customerListInfo']['customerList'][0]
        machine_room_community = Community.query.filter_by(community_name=customer_info['communityName']).all()
        machine_room_list = []
        permitted_machine_room = get_machine_room_by_area(session.get('permit_machine_room'))
        print(permitted_machine_room)
        pmid = [mid[0] for mid in permitted_machine_room]
        print(pmid)
        for cm in machine_room_community:
            machineroom_info = MachineRoom.query.filter_by(id=cm.machine_room_id).first()
            if str(machineroom_info.id) in pmid:
                machine_room_list.append((str(machineroom_info.id), machineroom_info.name))
        if len(machine_room_list) > 0:
            form = OntRegisterForm(machine_room_list)
            print(customer_info)
        else:
            flash('无对应上联机房')
            return render_template('index.html')
    else:
        logger.debug('no customer info return')
        #return render_template('index.html')
        customer_info = []
        form = OntRegisterFormByManager()

    if form.validate_on_submit():
        logger.info('User {} is registing an ONU {} in machine room {}, the ONU model is {}, service type is {}'.
                    format(session['LOGINNAME'],
                           form.mac.data,
                           form.machine_room_name.data,
                           form.ont_model_choice.data,
                           form.service_type.data))

        mac = form.mac.data.upper()
        ont_model = form.ont_model_choice.data
        service_type = form.service_type.data

        username = customer_info.get('accountId') if customer_info else account_id
        remarks = customer_info.get('currentState') if customer_info else account_id
        user_addr = customer_info.get('communityName') + '/' + customer_info.get('aptNo') if customer_info else form.customer_distinct.data

        device_list = get_device_info(form.machine_room_name.data)

        if device_list:
            for device in device_list:
                args = {'reporter_name': session.get('LOGINNAME'),
                        'reporter_group': User.query.filter_by(email=session.get('LOGINUSER')).first().area,
                        'register_name': session.get('LOGINNAME'),
                        'remarks': remarks,
                        'username': username,
                        'user_addr': user_addr,
                        'mac': mac,
                        'ip': device.ip,
                        'login_name': device.login_name,
                        'login_password': device.login_password,
                        'ont_model': ont_model,
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
        return render_template('ont_register_from_accountid.html',
                               form=form,
                               js=customer_info, account_id=account_id)
    else:
        return render_template('index.html')