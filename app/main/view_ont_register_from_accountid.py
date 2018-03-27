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
    loginName = User.query.filter_by(email=session['LOGINUSER']).first().workorder_login_name
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
        return jsonify(json.dumps({'status': '用户信息查询失败 请确认工单平台账号设置正确  请确认已开户'}))


@main.route('/regist_precheck', methods=['POST'])
@login_required
@permission_required(Permission.COMMENT)
def regist_precheck():
    """
    record_flag = {'1': 'modify onu', '2': 'alternate pon', '3': 'other', '4': 'new register'}
    :return:
    """
    account_id = request.form.get('account_id')
    mac = request.form.get('mac').upper()
    machine_room_id = request.form.get('machine_room_id')
    currentState = request.form.get('currentState')
    customerAddr = request.form.get('communityName') + '/' + request.form.get('aptNo')
    ont_model_choice = request.form.get('ont_model_choice')
    service_type = request.form.get('service_type')

    # 查找该机房下是否有对应的光猫，如果未找到则直接返回用户信息，不进行下面代码
    autofind_result = ont_autofind_func(machine_room_id, mac)
    if not autofind_result:
        return jsonify({"status": "fail", "content": "在所选机房未找到此光猫（{}）".format(mac)})

    # 查找历史的注册记录，可能有多条
    ont_regist_check = OntRegister.query.filter_by(username=account_id, status=1).all()

    # 验证历史注册记录中的信息与设备上的配置，主要是接口相符；正常情况，verify_onu_location只会有一条
    # 如若注册记录和实际配置相符合，则会append记录到此list中
    verify_onu_location = []

    for the_ont_record in ont_regist_check:
        the_location = ontLocation(device_id=the_ont_record.device_id, mac=the_ont_record.mac)
        if not the_location:
            break
        print(the_location[the_ont_record.device_id][0], the_location[the_ont_record.device_id][1])
        print('the location: ', the_location)
        if the_location and tuple(the_location[the_ont_record.device_id][0].split('/')) == (
                the_ont_record.f, the_ont_record.s, the_ont_record.p):
            verify_onu_location.append((the_ont_record, the_location[the_ont_record.device_id][1]))

    # 用于注册新ONU的参数
    args = {'reporter_name': session.get('LOGINNAME'),
            'reporter_group': User.query.filter_by(email=session.get('LOGINUSER')).first().area,
            'register_name': session.get('LOGINNAME'),
            'remarks': currentState,
            'username': account_id,
            'user_addr': customerAddr,
            'mac': mac,
            'ip': '',
            'login_name': '',
            'login_password': '',
            'ont_model': ont_model_choice,
            'device_id': '',
            'status': 1,
            'service_type': service_type,
            'api_version': 0.1    # 如果没有api_version参数，则注册函数返回值为数值，非jason，新版本会报错
            }

    # 如果上述验证都存在，则判断是换口还是换猫
    if ont_regist_check and verify_onu_location:
        regist_history = []

        # 这个for循环来具体区分采用什么操作
        for index, (record, ontId) in enumerate(verify_onu_location):
            print(record)
            for device_id, fsp in autofind_result.items():
                print("autofind result:", device_id, fsp, mac)
                print("history:", record.device_id, record.s, record.p, record.mac)
                if not fsp:
                    # 如果fsp为 False， 表示在这个设备上未找到ONU
                    continue
                now_f, now_s, now_p = fsp.split('/')
                if [now_f, now_s, now_p] == ['0', record.s, record.p] and device_id == record.device_id:
                    # 标记换猫
                    regist_history.append({"record_obj": record,
                                           "fromOntId": ontId,
                                           "action": "1",
                                           "from_mac": record.mac,
                                           "to_mac": mac,
                                           "now_device_id": device_id,
                                           "now_s": now_s,
                                           "now_p": now_p})
                elif device_id != record.device_id or now_s != record.s or now_p != record.p:
                    # 标记换口 允许onu mac 相同。
                    regist_history.append({"record_obj": record,
                                           "fromOntId": ontId,
                                           "action": "2",
                                           "device_id": device_id,
                                           "from_device": record.device_id,
                                           "from_fsp": "0/" + record.s + "/" + record.p,
                                           "from_mac": record.mac,
                                           "to_device": device_id,
                                           "to_fsp": "0/" + now_s + "/" + now_p,
                                           "to_mac": mac})
                else:
                    # 标记为其它未考虑因素
                    regist_history.append({"record_obj": record, "action": "3"})

        if not regist_history:
            # 如果regist_history为空，表示没有找到需要注册的ONU，原则上不会运行到这个判断。为老代码，暂不删除
            return jsonify({"status": "fail", "content": "在所选机房未找到此光猫（{}）".format(mac)})
        else:
            # 使用operate_cache来存放四要素信息（device_id, slot, port, mac），如果存在，表明这条历史注册记录已经被处理过
            operate_cache = []

            for record_action in regist_history:
                robj = record_action["record_obj"]
                if (robj.device_id, robj.s, robj.p, robj.mac) in operate_cache:
                    # 如果四要素在operate_cache中，表示已经出了相同的记录，此处发现重复的注册记录，直接将记录状态修改为998，即为删除
                    robj.status = 998
                    db.session.add(robj)
                    db.session.commit()
                else:
                    # 为操作过的记录，直接先cache下来，用于后续判断是否有重复记录
                    operate_cache.append((robj.device_id, robj.s, robj.p, robj.mac))

                    # 如果不存在四要素的cache，说明是第一次匹配到这条历史记录
                    # 以下是进行具体的换猫、换口等操作
                    if record_action["action"] == "1":
                        # 换猫操作，其中的ontid为实际目前的ontid
                        logger.info("do ont modify for record {}".format(robj.id))
                        modify_result = ont_modify_func(robj.device_id, robj.f, robj.s, robj.p,
                                                        record_action['fromOntId'], mac, force=True)

                        if modify_result['status'] == 'ok':
                            # 更新历史记录状态为997， 表示换猫记录
                            robj.status = 997
                            record_action["return_info"] = "\t换猫： 从{}换成{}".format(record_action['from_mac'],
                                                                                  record_action['to_mac'])
                            new_record = OntRegister(f=robj.f, s=robj.s, p=robj.p, mac=mac,
                                                     cevlan=robj.cevlan, ont_id=robj.ont_id,
                                                     device_id=robj.device_id,
                                                     ont_model=robj.ont_model,
                                                     regist_status=robj.regist_status,
                                                     username=robj.username,
                                                     user_addr=customerAddr,
                                                     reporter_name=session.get('LOGINNAME'),
                                                     reporter_group=User.query.filter_by(
                                                         email=session['LOGINUSER']).first().area,
                                                     regist_operator=session.get('LOGINNAME'),
                                                     remarks=json.dumps({"modify_reson": record_action["action"],
                                                                         "account_current_status": currentState}),
                                                     status=1,
                                                     create_time=time.localtime(),
                                                     update_time=time.localtime())

                            db.session.add(new_record)
                            db.session.commit()

                            modify_record = RegisterModify(from_id=robj.id,
                                                           to_id=new_record.id,
                                                           modify_reason=record_action["action"],
                                                           account_current_status=currentState,
                                                           create_time=time.localtime())
                            db.session.add(modify_record)
                            db.session.add(robj)
                            for r in ont_regist_check:
                                if r.id != robj.id:
                                    r.status = 998
                                    db.session.add(r)
                            db.session.commit()
                            session['REGIST_RESULT'] = modify_result['content']
                            return jsonify(modify_result)
                        else:
                            session['REGIST_RESULT'] = modify_result['content']
                            return jsonify(modify_result)

                    elif record_action["action"] == "2":
                        # 换口
                        # 更新历史记录状态为996， 表示换口，这里直接使用release_ont_func方法，会对历史记录状态进行调整
                        release_result = release_ont_func(robj.device_id, robj.f, robj.s, robj.p,
                                                          record_action['fromOntId'], robj.mac, to_status=996)
                        if not release_result:
                            return jsonify({"status": "fail", "content": "换口操作中释放历史ONU失败，请联系值班网管"})

                        # flash("原纪录光猫已删除")

                        # 若释放成功，则开始注册操作
                        args['device_id'] = record_action['device_id']
                        args['remarks'] = json.dumps({"modify_reason": record_action["action"],
                                                      "account_current_status": currentState})
                        args['force'] = True
                        register_result = ont_register_func(**args)

                        # api_version 为0.1 返回消息格式为{"status": "", "content": ""}
                        if register_result.get('status') == 'ok':
                            # 如果注册成功，则写入变更记录
                            modify_record = RegisterModify(from_id=robj.id,
                                                           to_id=register_result['content'],
                                                           modify_reason=record_action["action"],
                                                           account_current_status=currentState,
                                                           create_time=time.localtime())
                            db.session.add(modify_record)
                            for r in ont_regist_check:
                                if r.id != robj.id:
                                    r.status = 998
                                    db.session.add(r)
                            db.session.commit()
                            # 此处注册成功不需要flash message到网页上，因为ont_register_func中有对应的flash message
                            session['REGIST_RESULT'] = '换口成功，新ONU已成功注册，请确认用户上网是否正常'
                            return jsonify(register_result)
                        else:
                            # 回滚原先记录
                            robj.status = 1
                            db.session.add(robj)
                            db.session.commit()
                            return jsonify({"status": "fail", "content": register_result["content"]})

                    elif record_action["action"] == "3":
                        return jsonify({"status": "fail", "content": "注册异常，请联系技术部值班网管"})

            return jsonify({"status": "ok", "content": [r["return_info"] for r in regist_history]})

    elif not verify_onu_location or not ont_regist_check:
        # 开始新光猫注册
        for device_id, fsp in autofind_result.items():
            print("autofind result:", device_id, fsp, mac)
            if not fsp:
                # 例如一个机房下有多台OLT的情况，那么autofind_result可能会有多条记录
                # 如果fsp为 False， 表示在这个设备上未找到ONU
                continue
            else:
                args['device_id'] = device_id
                args['remarks'] = json.dumps({"modify_reason": "4",
                                              "account_current_status": currentState})
                args['force'] = True
                register_result = ont_register_func(**args)

                # api_version 为0.1 返回消息格式为{"status": "", "content": ""}
                if register_result.get('status') == 'ok':
                    # 删除历史记录中无用的信息
                    if ont_regist_check:
                        for r in ont_regist_check:
                            r.status = 998
                            modify_record = RegisterModify(from_id=r.id,
                                                           to_id=register_result['content'],
                                                           modify_reason="998",
                                                           account_current_status=currentState,
                                                           create_time=time.localtime())
                            db.session.add(modify_record)
                            db.session.add(r)

                            # 执行标记删除操作
                            for rr in ont_regist_check:
                                if rr.id != r.id:
                                    rr.status = 998
                                    db.session.add(rr)
                        db.session.commit()
                    logger.info("register {} on {} successful".format(mac, device_id))
                    session['REGIST_RESULT'] = '新ONU已成功注册，请确认用户上网是否正常'

                    return jsonify({"status": "ok", "content": "注册成功，请确认用户上网正常"})
                else:
                    return jsonify({"status": "fail", "content": register_result["content"]})

        return jsonify({'status': 'new_delOld', 'content': '注册记录信息与实际设备配置不付，重新注册并删除旧的注册记录'})


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

    loginName = User.query.filter_by(email=session['LOGINUSER']).first().workorder_login_name
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
        print('no customer info return')
        return render_template('index.html')

    if form.validate_on_submit():
        logger.info('User {} is registing an ONU {} in machine room {}, the ONU model is {}, service type is {}'.
                    format(session['LOGINNAME'],
                           form.mac.data,
                           form.machine_room_name.data,
                           form.ont_model_choice.data,
                           form.service_type.data))

        session['MAC'] = form.mac.data.upper()
        session['CUSTOMERNUMBER'] = customer_info.get('accountId')
        session['ONTMODEL'] = form.ont_model_choice.data
        service_type = form.service_type.data

        device_list = get_device_info(form.machine_room_name.data)

        if device_list:
            for device in device_list:
                args = {'reporter_name': session.get('LOGINNAME'),
                        'reporter_group': User.query.filter_by(email=session.get('LOGINUSER')).first().area,
                        'register_name': session.get('LOGINNAME'),
                        'remarks': customer_info.get('currentState'),
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
        return render_template('ont_register_from_accountid.html',
                               form=form,
                               js=customer_info)
    else:
        return render_template('index.html')
