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
        try:
            find_exist_ont = ontLocation(machine_room=machine_room_id, mac=mac)
            logger.debug(str(find_exist_ont))
            if find_exist_ont:
                for device_id, ont_info in find_exist_ont.items():
                    change_result = change_service(olt_name=device_id, ports_name=None, service_type=service_type,
                                                   mac={'mac': mac, 'info': ont_info})
                    if change_result['status'] == 'true':
                        return jsonify({"status": "ok", "content": "变更服务成功"})
                    else:
                        return jsonify({"status": "fail", "content": "变更服务失败"})
            else:
                return jsonify({"status": "fail", "content": "在所选机房未找到此光猫（{}）".format(mac)})
        except:
            return jsonify({"status": "fail", "content": "在所选机房未找到此光猫（{}）".format(mac)})

    # 查找历史的注册记录，可能有多条
    ont_regist_check = OntRegister.query.filter_by(username=account_id, status=1).all()

    # 验证历史注册记录中的信息与设备上的配置，主要是接口相符；正常情况，verify_onu_location只会有一条
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

    # 用于注册新ONU的变量
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
            'api_version': 0.1
            }

    # 如果上述验证都存在，则判断是换口还是换猫
    if ont_regist_check and verify_onu_location:
        regist_history = []
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
            # 使用operate_cache来存放四要素信息，如果存在，表明这条历史注册记录已经被处理过
            operate_cache = []
            print(regist_history)
            for record_action in regist_history:
                print(record_action)
                robj = record_action["record_obj"]
                if (robj.device_id, robj.s, robj.p, robj.mac) in operate_cache:
                    robj.status = 998
                    db.session.add(robj)
                    db.session.commit()
                else:
                    operate_cache.append((robj.device_id, robj.s, robj.p, robj.mac))

                    # 如果不存在四要素的cache，说明是第一次匹配到这条历史记录
                    if record_action["action"] == "1":
                        # 换猫

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
                                                         email=session.get('LOGINUSER')).first().area,
                                                     regist_operator=session.get('LOGINNAME'),
                                                     remarks=json.dumps({"modify_reason": record_action["action"],
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
        for device_id, fsp in autofind_result.items():
            print("autofind result:", device_id, fsp, mac)
            if not fsp:
                # 如果fsp为 False， 表示在这个设备上未找到ONU
                continue
            else:
                # 若释放成功，则开始注册操作
                args['device_id'] = device_id
                args['remarks'] = json.dumps({"modify_reason": "4",
                                              "account_current_status": currentState})
                args['force'] = True
                register_result = ont_register_func(**args)

                # api_version 为0.1 返回消息格式为{"status": "", "content": ""}
                if register_result.get('status') == 'ok':
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
