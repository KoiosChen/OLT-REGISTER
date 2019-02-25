import queue
import threading
import re
import time
from datetime import datetime
from .models import MachineRoom, Device, AccountInfo, ONTDetail, MacLearnedByONT, OntRegister, CeVlan, ServicePort, \
    PeVlan
from .telnet_device import Telnet5680T, TelnetME60
from . import db, logger
from sqlalchemy import or_, update
from .MyModule import SaveData, OntStatus
from flask import flash, session
from collections import defaultdict
import sys
import random


def get_machine_room_by_area(permit_machine_room):
    logger.debug('get machine room param: {}'.format(permit_machine_room))
    logger.debug('the session id is {}'.format(session.sid))
    if not permit_machine_room:
        flash('获取权限异常,请尝试注销后完全关闭页面并重新登陆')
        permit_machine_room = '0x0'
    return [(str(k.id), k.name)
            for k in MachineRoom.query.filter(MachineRoom.status != 0).all()
            if int(k.permit_value, 16) & int(permit_machine_room, 16) == int(k.permit_value, 16)]


def get_device_name():
    return [(str(k.id), k.device_name) for k in Device.query.all()]


def get_device_info(machine_room_id):
    """
    :param machine_room_id:
    :return:
    """
    device_info = Device.query.filter_by(machine_room_id=machine_room_id, status=1).all()
    return device_info if device_info else []


class StartThread(threading.Thread):
    def __init__(self, q, func):
        threading.Thread.__init__(self)
        self.queue = q
        self.func = func
        print('thread', func)

    def run(self):
        while True:
            id = self.queue.get()
            try:
                self.func(id)
            except Exception as e:
                print('thread %s' % e)
                sys.exit(1)

            self.queue.task_done()


def GetBASEInfo(start=1, stop=3, domain='pppoe'):
    logger.info('GetBaseInfo')
    bas = {'bx-me60': {'ip': '172.30.2.4', 'username': 'monitor', 'password': 'Gwbnsh@408'},
           'csgn-me60': {'ip': '172.30.4.10', 'username': 'monitor', 'password': 'Gwbnsh@408'}}
    for name, device in bas.items():
        tlnt = TelnetME60.TelnetDevice(host=device['ip'], username=device['username'], password=device['password'])
        result = tlnt.get_access_user_by_domain(domain)

        for username, int, sub_int, ip, mac in result:
            username_indb = AccountInfo.query.filter_by(username=username, interface=int, sub_int=sub_int,
                                                        mac=mac).first()
            if not username_indb:
                db_action = AccountInfo(username=username, interface=int, sub_int=sub_int, mac=mac, bas_name=name,
                                        ip=ip, create_time=time.localtime(), update_time=time.localtime())
                db.session.add(db_action)
            else:
                username_indb.update_time = time.localtime()
                db.session.add(username_indb)
        db.session.commit()
        tlnt.telnet_close()


def ont_learned_by_mac(id):
    import re
    device_id = id
    device_info = Device.query.filter_by(id=device_id).first()
    try:
        t = Telnet5680T.TelnetDevice(mac='', host=device_info.ip, username=device_info.login_name,
                                     password=device_info.login_password)

        ont_list = ONTDetail.query.filter_by(device_id=device_id).all()
    except Exception as e:
        logger.error(e)
        return 500

    for ont in ont_list:
        logger.debug(ont.f + ' ' + ont.s + ' ' + ont.p + ' ' + str(ont.ont_id))
        vlanid = CeVlan.query.filter_by(device_id=device_id, s=ont.s, p=ont.p, ont_id=str(ont.ont_id)).first()
        mac_list = t.display_mac_learned_by_ont(f=ont.f, s=ont.s, p=ont.p, ontid=str(ont.ont_id),
                                                vlanid=vlanid.cevlan if vlanid else '')
        if mac_list:
            for line in mac_list:
                mac = re.findall(r'([0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4})', line)
                if mac:
                    mac_indb = MacLearnedByONT.query.filter_by(ont_mac=ont.mac, learned_mac=mac[0]).first()
                    if not mac_indb:
                        db_act = MacLearnedByONT(ont_mac=ont.mac, learned_mac=mac[0], ontinfo_id=ont.id,
                                                 create_time=time.localtime(), update_time=time.localtime())
                        db.session.add(db_act)
                    else:
                        mac_indb.update_time = time.localtime()
                        db.session.add(mac_indb)

                    logger.info('{} {}'.format(ont.mac, mac[0]))
                db.session.commit()
        else:
            logger.debug('not find on {}/{}/{} - {}'.format(ont.f, ont.s, ont.p, ont.ont_id))


def diagnose_display_elabel(id):
    import re
    device_id = id
    device_info = Device.query.filter_by(id=device_id).first()
    t = Telnet5680T.TelnetDevice(mac='', host=device_info.ip, username=device_info.login_name,
                                 password=device_info.login_password)

    t.go_into_diagnose()
    print_flag = False

    with open(device_info.device_name, mode='w') as f:

        for line in t.display_elabel():
            if re.search('System Integration Version', line) and not print_flag and line[:-1]:
                print_flag = True

            if print_flag and line[:-1] and not re.search('/\$', line):
                print(line)
                f.write(line + '\r\n')


def get_ont_detail_info(tlnt, frame, slot, port, ont_id):
    tlnt.go_into_interface_mode('/'.join([frame, slot, port]))
    ont_detail_info = tlnt.display_ont_detail_info(port, ont_id)
    for line in ont_detail_info:
        if re.search(r'Line profile ID', line):
            l_id = re.findall(r'(\d+)', line)[0]
        if re.search(r'Line profile name', line):
            l_name = re.findall(r':\s*(\w+\-*\w+)', line)[0]
        if re.search(r'Service profile ID', line):
            s_id = re.findall(r'(\d+)', line)[0]
        if re.search(r'Service profile name', line):
            s_name = re.findall(r':\s*(\w+\-*\w+)', line)[0]
    if s_name and s_id and l_name and l_id:
        return s_name, s_id, l_name, l_id
    else:
        return False, False, False, False


def update_ont_info(id):
    device_id = id
    device_info = Device.query.filter(Device.id.__eq__(device_id), Device.status.__ne__(0)).first()
    if device_info:
        tlnt = Telnet5680T.TelnetDevice(mac='',
                                        host=device_info.ip,
                                        username=device_info.login_name,
                                        password=device_info.login_password)
        ont_list = ONTDetail.query.filter_by(device_id=device_id).all()
        for ont in ont_list:
            print(ont)
            tlnt.go_into_interface_mode('/'.join([ont.f, ont.s, ont.p]))
            # get the optical power info
            optical = tlnt.check_optical_info(p=str(ont.p), id=str(ont.ont_id))
            if 'Failure' not in '\n'.join([line for line in optical]):
                for i in optical:
                    if i.strip()[:-1] and re.search(r':', str(i)):
                        content = i.strip().replace(' ', '').split(':')[1].split(',')[0].strip('\'')
                        # The if ... elif below is used to handle the content to digital when it include some string
                        if content == '-' or content == '[-':
                            content = '0.0'
                        if re.search(r'Rx optical power|Rx Optical Power', str(i)):
                            ont.rx_optical_power = re.findall(r'(\-?[0-9]+\.?[0-9]*)', str(content))[0]
                        elif re.search(r'Voltage', str(i)):
                            ont.voltage = re.findall(r'(\-?[0-9]+\.?[0-9]*)', str(content))[0]
                        elif re.search(r'Temperature\(C\)', str(i)):
                            ont.temperature = re.findall(r'(\-?[0-9]+\.?[0-9]*)', str(content))[0]
                        elif re.search(r'OLT Rx ONT optical power|OLT Rx ONT Optical Power', str(i)):
                            ont.olt_rx_ont_optical_power = re.findall(r'(\-?[0-9]+\.?[0-9]*)', str(content))[0]

                # get the last down cause
                register_info = tlnt.check_register_info(p=str(ont.p), id=str(ont.ont_id))
                flag = [False, False, False]
                for line in register_info:
                    if line.strip()[:-1] and re.search(r':', str(line)):
                        if re.search(r'UpTime', str(line)) and not flag[0]:
                            uptime = ':'.join(line.strip().split(':')[1:]).strip().split('+')[0]
                            if uptime != '-':
                                print(uptime)
                                ont.last_up_time = datetime.strptime(uptime, "%Y-%m-%d %H:%M:%S")
                                print(datetime.strptime(uptime, "%Y-%m-%d %H:%M:%S"))
                                flag[0] = True
                        elif re.search(r'DownTime', str(line)) and not flag[1]:
                            downtime = ':'.join(line.strip().split(':')[1:]).strip().split('+')[0]
                            if downtime != '-':
                                ont.last_down_time = datetime.strptime(downtime, "%Y-%m-%d %H:%M:%S")
                                print(datetime.strptime(downtime, "%Y-%m-%d %H:%M:%S"))
                                flag[1] = True
                        elif re.search(r'DownCause', str(line)) and not flag[2]:
                            last_down_cause = line.strip().split(':')[1].strip('\'').strip()
                            if last_down_cause != '-':
                                ont.last_down_cause = last_down_cause
                                print(line.strip().split(':')[1].strip('\''))
                                flag[2] = True
                db.session.add(ont)
            else:
                print('deleting ont {}'.format(ont.mac))
                db.session.delete(ont)
            db.session.commit()
        tlnt.telnet_close()
    else:
        logger.warn('device {} 不可用'.format(id))


def AnalysisONT(id):
    device_id = id
    device_info = Device.query.filter_by(id=device_id).first()
    tlnt = Telnet5680T.TelnetDevice(mac='', host=device_info.ip, username=device_info.login_name,
                                    password=device_info.login_password)
    if not device_info.status:
        print('status %s. This device is not available' % device_info.status)
        return False

    # get the number of boards
    board_id_list = [line.strip().split()[0] for line in tlnt.check_board_info()]

    # Get the ONT info and insert or update to DB
    for bid in board_id_list:
        ont_list, port_list = tlnt.check_board_info(slot=bid)
        print(port_list)
        x = 0
        for i in ont_list:
            i = i.replace('b\'', '')
            if re.search(r'total of ONTs', str(i)):
                x += 1
                continue
            try:
                print(i.strip().split()[:9])
                f, s_p, ont_id, mac, control_flag, run_state, config_state, match_state, protect_side = i.strip().split()[
                                                                                                        :9]
                f = f.replace('/', '')
                s, p = s_p.split('/')
            except Exception as e:
                try:
                    print(i.split()[:8])
                    f_s_p, ont_id, mac, control_flag, run_state, config_state, match_state, protect_side = i.strip().split()[
                                                                                                           :8]
                    f, s, p = f_s_p.split('/')
                except Exception as e:
                    print(i.split()[:7])
                    f = '0'
                    s = bid
                    ont_id, mac, control_flag, run_state, config_state, match_state, protect_side = i.strip().split()[
                                                                                                    :7]
                    p = port_list[x]
                    print(p)

            ont_info = ONTDetail.query.filter_by(mac=mac).first()
            if ont_info:
                print(
                    'mac exist {} {}/{}/{}, ont_id:{}'.format(mac, ont_info.f, ont_info.s, ont_info.p, ont_info.ont_id))
                if ont_info.f == f and ont_info.s == s and ont_info.p == p and str(ont_info.ont_id) == ont_id:
                    ont_info.update_time = time.localtime()
                    ont_info.control_flag = control_flag
                    ont_info.run_state = run_state
                    ont_info.match_state = match_state
                else:
                    print('mac exist, but changed port or ont_id {}'.format(mac))
                    ont_info.ont_status = 2
                    ont_new = ONTDetail(device_id=id, f=f, s=s, p=p, ont_id=ont_id,
                                        mac=mac, control_flag=control_flag,
                                        run_state=run_state, config_state=config_state,
                                        match_state=match_state, protect_side=protect_side,
                                        pre_id=ont_info.id,
                                        create_time=time.localtime(), update_time=time.localtime())
                    db.session.add(ont_new)
            else:
                print(mac)
                if re.search(r'^[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}', mac):
                    ont_info = ONTDetail(device_id=id, f=f, s=s, p=p, ont_id=ont_id,
                                         mac=mac, control_flag=control_flag,
                                         run_state=run_state, config_state=config_state,
                                         match_state=match_state, protect_side=protect_side,
                                         create_time=time.localtime(), update_time=time.localtime())
                else:
                    continue
            db.session.add(ont_info)
        try:
            db.session.commit()
        except Exception as e:
            print(e)
            db.session.rollback()

    tlnt.telnet_close()


def get_ont_detail(id):
    xtime = datetime.now()
    logger.info('Get ONT information on device {} at {}'.format(id, xtime))
    device_id = id
    device_info = Device.query.filter_by(id=device_id).first()

    if not device_info.status:
        logger.warning('Status %s. This device is not available in func \'AnalysisONT\'' % device_info.status)
        exit()

    tlnt = Telnet5680T.TelnetDevice(mac='', host=device_info.ip, username=device_info.login_name,
                                    password=device_info.login_password)

    # get the number of boards
    board_id_list = [line.strip().split()[0] for line in tlnt.check_board_info()]
    logger.debug(board_id_list)

    # Get the ONT info and insert or update to DB
    for bid in board_id_list:
        ont_list, port_list = tlnt.check_board_info(slot=bid)
        logger.debug(port_list)
        # x 用来针对部分OLT版本, 根据total of ONTs来确认相关数据, x用来计数, 针对每个板卡
        x = 0
        for i in ont_list:
            i = i.replace('b\'', '')
            if re.search(r'total of ONTs', str(i)):
                x += 1
                continue
            try:
                ont_id, mac, control_flag, run_state, config_state, match_state, protect_side = \
                    re.findall(
                        r'(\d+)\s+([0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4})\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\w+)',
                        i.strip())[0]
                f = '0'
                s = str(bid)
                p = str(port_list[x])
                print(ont_id, mac, control_flag, run_state, config_state, match_state, protect_side, f, s, p)

                s_name, s_id, l_name, l_id = get_ont_detail_info(tlnt, f, s, p, ont_id)
                print(s_name, s_id, l_name, l_id)
                tlnt.quit()

                ont_select_if_exist = ONTDetail.query.filter(ONTDetail.mac.__eq__(mac)).all()

                if len(ont_select_if_exist) > 0:
                    logger.debug('device {} mac {} has record {} in db'.format(device_id, mac, ont_select_if_exist))
                    logger.debug(ont_select_if_exist)
                    on_same_fsp = False
                    already_exist_online = False

                    for ont_info in ont_select_if_exist:
                        if ont_info.device_id == device_id and \
                                ont_info.f == f and \
                                ont_info.s == s and \
                                ont_info.p == p and \
                                str(ont_info.ont_id) == ont_id:
                            on_same_fsp = ont_info.id
                        if ont_info.run_state == 'online' and ont_info.update_time >= xtime and not on_same_fsp:
                            already_exist_online = True

                    if run_state == 'online':
                        run_status = 1
                        other_status = 910 if already_exist_online else 900
                    else:
                        run_status = 2
                        other_status = 900 if already_exist_online else 901

                    if on_same_fsp:
                        ont_1 = ONTDetail.query.filter_by(id=on_same_fsp).first()
                        ont_1.update_time = time.localtime()
                        ont_1.control_flag = control_flag
                        ont_1.run_state = run_state
                        ont_1.ont_status = run_status \
                            if (other_status != 901 and other_status != 910 and other_status != 900) \
                               or len(ont_select_if_exist) == 1 \
                            else other_status
                        ont_1.match_state = match_state
                        db.session.add(ont_1)

                        for ont_other_update in ont_select_if_exist:
                            if ont_other_update.id != on_same_fsp:
                                ont_other_update.ont_status = other_status
                                db.session.add(ont_other_update)
                    else:
                        run_status = run_status \
                            if other_status != 901 and other_status != 910 and other_status != 900 \
                            else other_status
                        ont_info = ONTDetail(device_id=id, f=f, s=s, p=p, ont_id=ont_id,
                                             mac=mac, control_flag=control_flag,
                                             run_state=run_state, config_state=config_state,
                                             match_state=match_state, protect_side=protect_side,
                                             ont_status=run_status,
                                             server_profile_name=s_name,
                                             server_profile_id=s_id,
                                             line_profile_name=l_name,
                                             line_profile_id=l_id,
                                             create_time=time.localtime(), update_time=time.localtime())

                        db.session.add(ont_info)

                        for ont_other_update in ont_select_if_exist:
                            ont_other_update.ont_status = other_status
                            db.session.add(ont_other_update)
                else:
                    run_status = 1 if run_state == 'online' else 2
                    ont_info = ONTDetail(device_id=id, f=f, s=s, p=p, ont_id=ont_id,
                                         mac=mac, control_flag=control_flag, ont_status=run_status,
                                         run_state=run_state, config_state=config_state,
                                         match_state=match_state, protect_side=protect_side,
                                         server_profile_name=s_name,
                                         server_profile_id=s_id,
                                         line_profile_name=l_name,
                                         line_profile_id=l_id,
                                         create_time=time.localtime(), update_time=time.localtime())

                    db.session.add(ont_info)

                db.session.commit()

            except Exception as e:
                if not re.search(r'------', i):
                    logger.debug(i)
                    logger.debug('OLT output format error, device id {} for reason {}'.format(device_id, e))

    tlnt.telnet_close()
    print('device {} finished'.format(device_id))


def create_filename(prefix):
    return prefix + '-' + time.strftime('%Y-%m-%d', time.localtime(time.time())) + r'.xlsx'


def test():
    """
    用于计算每个PON口是光衰情况
    :return:
    """
    head = ['f/s/p', '总ONT数量', 'LOSI下线用户', '光衰大于28DB数量', 'LOSI占比', '光衰大用户占比']
    col_start = 1
    row_start = 1
    c_l = 'c'
    dest_file = create_filename('per_pon_statistics')
    for device_id in Device.query.all():
        print_data = []
        print_data.append(head)
        print(device_id.machine_room.name)
        for f in [i.f for i in
                  ONTDetail.query.group_by('f').filter_by(device_id=device_id.id, run_state='online').all()]:
            for s in [i.s for i in
                      ONTDetail.query.group_by('s').filter_by(device_id=device_id.id, f=f, run_state='online').all()]:
                for p in [i.p for i in ONTDetail.query.group_by('p').filter_by(device_id=device_id.id, f=f, s=s,
                                                                               run_state='online').all()]:
                    print('{}/{}/{}'.format(f, s, p), end='\t')
                    total = ONTDetail.query.filter(ONTDetail.device_id == device_id.id,
                                                   ONTDetail.f == f,
                                                   ONTDetail.s == s,
                                                   ONTDetail.p == p).count()
                    losi = ONTDetail.query.filter(ONTDetail.device_id == device_id.id,
                                                  ONTDetail.f == f,
                                                  ONTDetail.s == s,
                                                  ONTDetail.p == p,
                                                  ONTDetail.last_down_cause.like('%LOS%')).count()
                    rx_31 = ONTDetail.query.filter(ONTDetail.device_id == device_id.id,
                                                   ONTDetail.f == f,
                                                   ONTDetail.s == s,
                                                   ONTDetail.p == p,
                                                   or_(ONTDetail.rx_optical_power < -28,
                                                       ONTDetail.olt_rx_ont_optical_power < -28)).count()
                    if not total:
                        print('{}   {}  {}  {}%    {}%'.format(total, losi, rx_31, int(losi / total * 10000) / 100,
                                                               int(rx_31 / total * 10000) / 100), end='')
                        print_data.append([str(f) + '/' + str(s) + '/' + str(p), total, losi, rx_31,
                                           str(round((losi / total * 10000) / 100, 2)) + '%',
                                           str(round((rx_31 / total * 10000) / 100, 2)) + '%'])
                    else:
                        print('{}   {}  {}  {}%    {}%'.format(total, losi, rx_31, 0, 0), end='')
                        print_data.append([str(f) + '/' + str(s) + '/' + str(p), total, losi, rx_31, '0%', '0%'])
                    print()
        init_info = {'dest_file': '/Users/Peter/python/founderbn_nmp/' + dest_file,
                     'c_l': c_l,
                     'data': print_data,
                     'col_start': col_start,
                     'row_start': row_start}

        if len(print_data) > 1:
            SaveData.save_data(device_id.machine_room.name, **init_info)

        c_l = 'l'


def ont_add_native_vlan(tlt, **kwargs):
    eth = {'1': '1', '2': '4', '3': '1'}
    ont_model = kwargs.get('ont_model', '1')
    device_id = kwargs.get('device_id')
    f = kwargs.get('f')
    s = kwargs.get('s')
    p = kwargs.get('p')
    service_type = kwargs.get('service_type')
    ont_id = kwargs.get('ont_id')
    mac = kwargs.get('mac')
    username = kwargs.get('username')
    user_addr = kwargs.get('project') + '/' + kwargs.get('number', '')
    reporter_group = kwargs.get('reporter_group', 'r2d2')
    reporter_name = kwargs.get('reporter_name', 'r2d2')
    register_name = kwargs.get('register_name', 'r2d2')
    remarks = kwargs.get('remarks', 'r2d2')
    eth_port = eth[ont_model]
    cevlan = get_cevlan(device_id, f, s, p, service_type)

    # {'remarks': 'unicom', 'service_type': '4', 'user_addr': 'unicom', 'device_id': 26, 'reporter_name': 'r2d2',
    #  'ont_id': '9', 'username': 'unicom', 'ont_model': '1', 'register_name': 'r2d2', 's': '4', 'mac': '001F-A4D6-B069',
    #  'p': '12', 'f': '0', 'reporter_group': 'r2d2'}

    if cevlan:
        # write log
        logger.info('Get the cevlan {}'.format(cevlan))

        # old method just support 1 port onu, not used yet
        # regist_status = 1 if tlt.ont_port_native_vlan_add(p, ont_id, eth_port, cevlan) else 4

        add_cevlan_flag = 0
        tlt.go_into_interface_mode(f + '/' + s + '/' + p)
        for e_port in range(1, int(eth_port) + 1):
            if tlt.ont_port_native_vlan_add(p, ont_id, str(e_port), cevlan):
                logger.debug('add ont on {} {} eth {} cevlan {}'.format(p, ont_id, str(e_port), cevlan))
                add_cevlan_flag += 1

        logger.debug('add_cevlan_flag: {}'.format(add_cevlan_flag))

        regist_status = 1 if add_cevlan_flag == int(eth_port) else 4

        # insert register log into database
        try:
            old_record = OntRegister.query.filter_by(mac=mac).all()
            if old_record:
                for r in old_record:
                    r.status = 998
                    r.update_time = time.localtime()
                    db.session.add(r)
                db.session.commit()

            ont_regist_data = OntRegister(f=f, s=s, p=p, mac=mac, cevlan=cevlan, ont_id=ont_id,
                                          device_id=device_id,
                                          ont_model=ont_model, regist_status=regist_status,
                                          username=username,
                                          user_addr=user_addr, reporter_name=reporter_name,
                                          reporter_group=reporter_group, regist_operator=register_name,
                                          remarks=remarks, status=regist_status,
                                          create_time=time.localtime(), update_time=time.localtime())
            ins_cevlan = CeVlan(f=f, s=s, p=p, device_id=device_id, cevlan=cevlan, ont_id=ont_id)
            db.session.add(ins_cevlan)
            db.session.add(ont_regist_data)
            db.session.commit()
            logger.info('Insert the ont register info into db successful')
            return {"status": "true", "content": ont_regist_data.id}
        except Exception as e:
            logger.error('Insert the ont register info error {}'.format(e))
            return {'status': 'false', 'content': str(e)}
    else:
        # write log
        logger.warning('No cevlan found')
        return {'status': 'false', 'content': 'Cannot find CEVLAN'}


def register_to_unicom():
    service_type = 4

    def _find_ont_location(mac):
        return ONTDetail.query.filter(ONTDetail.mac.__eq__(mac),
                                      or_(ONTDetail.ont_status.__eq__(1), ONTDetail.ont_status.__eq__(2),
                                          ONTDetail.run_state.__eq__('online'))).first()

    def _write_register_log(type, mac, content):
        with open('./register_to_unicom_result.log', 'a') as logfile:
            logfile.write("{} {} {}\n".format(type, mac, content))

    def _collect_register_info():
        import csv
        f = open('./source_onu_mac.csv')
        f_csv = csv.DictReader(f)
        dst_ont_list = defaultdict(list)
        for row in f_csv:
            ont_location = _find_ont_location(row['mac'])
            if ont_location:
                row['device_id'] = ont_location.device_id
                row['f'] = ont_location.f
                row['s'] = ont_location.s
                row['p'] = ont_location.p
                row['ont_id'] = ont_location.ont_id
                row['service_type'] = 4
                dst_ont_list[ont_location.device_id].append(row)
                _write_register_log('Locate', row['mac'], 'success')
            else:
                _write_register_log('Locate', row['mac'], 'fail')
        f.close()
        return dst_ont_list

    def _do_register(device_id, info):
        # 允许不传入ip， login_name, login_password, 通过device_id来查找数据库完成
        device_info = Device.query.filter_by(id=device_id).first()
        ip, login_name, login_password = device_info.ip, device_info.login_name, device_info.login_password

        # telnet olt
        try:
            tlt = Telnet5680T.TelnetDevice('', ip, login_name, login_password)
            for r in info:
                result = ont_add_native_vlan(tlt, **r)
                _write_register_log('Move', r['mac'], result['status'])
        except Exception as e:
            logger.error(str(e))

    register_info = _collect_register_info()
    i = 0
    t = []
    for device_id, info in register_info.items():
        t.append(i)
        t[i] = threading.Thread(target=_do_register, args=(device_id, info,))
        t[i].start()
        i += 1


def start_func():
    def select_func():
        func = (
            get_ont_detail, update_ont_info, diagnose_display_elabel, ont_learned_by_mac, sync_cevlan,
            sync_service_port)
        print('please select the func your want to start:')
        startfunc = []
        for num, key in enumerate(func):
            startfunc.append(key)
            print(num, ':', key.__name__)

        try:
            selected_num = int(input('select the num:'))
        except Exception:
            select_func()
        except KeyboardInterrupt:
            exit()

        try:
            func = startfunc[selected_num]
        except Exception:
            select_func()

        return func

    func = select_func()

    device_id_list = [device.id for device in Device.query.filter_by(status='1').all()]

    t = []

    for index, device in enumerate(device_id_list):
        logger.info('do {} on {}'.format(func, device))
        t.append(index)
        t[index] = threading.Thread(target=func, args=(device,))
        t[index].start()

    return True


def FindLOID(mac, ip, username, password):
    tlt = Telnet5680T.TelnetDevice(mac, ip, username, password)
    fsp = tlt.auto_find_onu()
    if fsp:
        print(fsp)
        p = tlt.go_into_interface_mode(fsp)
        loid_id = tlt.find_free_loid(p)
        if not loid_id:
            tlt.telnet_close()
            return 'noid'
        loid = tlt.find_loid(loid_id)
        if not loid:
            tlt.telnet_close()
            return 'noloid'
        tlt.telnet_close()
        return loid

    else:
        tlt.telnet_close()
        return False


def add_log(data):
    db.session.add(data)
    try:
        db.session.commit()
    except Exception as e:
        logger.error('add log error {}'.format(e))
        pass


def get_cevlan(device_id, f, s, p, service_type):
    """
    update @2017-03-08 for separation of pevlan
    update @2018-09-26 for CUCC, if there is not enough cevlan, then the program will select a cevlan random.
    :param device_id:
    :param f:
    :param s:
    :param p:
    :param service_type: 用于确认使用的外层vlan的类型, 1: 社区, 2: 商业, 3: 代理, 4: 联通 .....
    :return:
    """
    logger.info('start to get cevlan on device_id {} {}/{}/{}'.format(device_id, f, s, p))
    logger.info('regist the onu in cevlan as service type {}'.format(service_type))

    try:
        service_port = ServicePort.query.filter_by(device_id=device_id, f=f, s=s, p=p).all()
        source = []
        """
        2017-03-08 增加target_pevlan type list, 用于存放找到的PEVLAN, 后续查找CEVLAN的时候, 通过这些PEVLAN找到相关FSP来查找已经使用的
        celvan。 目的是使cevlan在该PEVLAN下不重复
        """
        target_pevlan = []

        for sp in service_port:
            # write log
            logger.debug('service port {}'.format(sp))

            pevlan = PeVlan.query.filter_by(device_id=device_id, pevlan=sp.pevlan).first()

            # write log
            logger.debug('find the pevlan({})\'s service type {}'.format(pevlan, pevlan.service_type))

            if pevlan.service_type == int(service_type):
                # write log
                logger.debug('find the service type, target vlan is {}'.format(pevlan.pevlan))
                target_pevlan.append(pevlan.pevlan)

                vlan_start, vlan_stop = re.findall(r'(\d+)-?(\d+)?', sp.cevlan_range)[0]
                vlan_stop = vlan_stop if vlan_stop else vlan_start

                # write log
                logger.debug('the pevlan\'s cevlan range is {}  to {}'.format(vlan_start, vlan_stop))

                source.extend(list(range(int(vlan_start), int(vlan_stop) + 1)))

        list2 = []
        # 2017-03-08 通过查找所有的pevlan对应的fsp, 然后通过fsp查找已经注册使用的cevlan,确保在一个pevlan下没有重复使用的cevlan
        target_fsp = []
        for tp in target_pevlan:
            sp_by_pevlan = ServicePort.query.filter_by(device_id=device_id, pevlan=tp).all()
            target_fsp.append([(pe.f, pe.s, pe.p) for pe in sp_by_pevlan])

        for frame, slot, port in set(target_fsp[0]):
            ont_regist_info = CeVlan.query.filter_by(device_id=device_id, f=frame, s=slot, p=port).all()
            if ont_regist_info:
                for info in ont_regist_info:
                    logger.debug(info)
                    if len(info.cevlan) > 0:
                        if int(info.cevlan) in source:
                            logger.debug('cevlan in source: {}'.format(info.cevlan))
                            list2.append(int(info.cevlan))
            else:
                list2.append(2)
        try:
            guess_cevlan = (min(set(source) - set(list2)))
        except Exception as e:
            logger.error(str(e))
            if source:
                guess_cevlan = random.choice(source)
            else:
                guess_cevlan = False
        return str(guess_cevlan) if guess_cevlan else False

    except ValueError:
        logger.error('does not find cevlan for {} {}/{}/{} {}'.format(device_id, f, s, p, service_type))
        return False


def ont_register_func(**kwargs):
    """
    :param :
        args = {'reporter_name': session.get('LOGINUSER'),
                        'reporter_group': '',
                        'register_name': session.get('LOGINUSER'),
                        'remarks': '',
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
    :return: 1 -- success; 2 -- ont not found; 3 -- ont found, but register failed
    """

    flash_message = {'1': '光猫注册成功, 请使用\'ONU查询\'功能确认ONU状态',
                     '2': '未发现光猫,请检查线路或联系网管',
                     '3': '发现光猫, 但添加ONT失败,请联系值班网管',
                     '4': '发现光猫并注册, 但是绑定native-vlan失败, 请联系值班网管',
                     '5': 'OLT远程管理失败',
                     '6': '此光猫已经被注册在其它PON口, 请联系值班网管',
                     '7': '此PON口已达到注册上线,请联系值班网管调整',
                     '104': '发现光猫并注册, 但是绑定native-vlan失败, 系统回滚成功, 请联系值班网管处理',
                     '107': '发现光猫并注册, 但设备native-vlan耗尽,系统回滚成功, 请联系值班网管处理',
                     '204': '发现光猫并注册, 但是绑定native-vlan失败, 系统回滚失败, 请联系值班网管处理',
                     '207': '发现光猫并注册, 但设备native-vlan耗尽,系统回滚失败, 请联系值班网管处理',
                     '998': 'onu被解绑',
                     '999': '未找到对应机房'}

    # eth dict: ont_model_choice_id: port number
    eth = {'1': '1', '2': '4', '3': '1'}
    srvprofile_dict = {'1': '1', '2': '2', '3': '10'}

    # initial args
    mac = kwargs.get('mac')
    ip = kwargs.get('ip')
    login_name = kwargs.get('login_name')
    login_password = kwargs.get('login_password')
    ont_model = kwargs.get('ont_model')
    device_id = kwargs.get('device_id')
    username = kwargs.get('username')
    user_addr = kwargs.get('user_addr')
    reporter_name = kwargs.get('reporter_name')
    reporter_group = kwargs.get('reporter_group')
    register_name = kwargs.get('register_name')
    # 20171031 重新定义remarks用途，用于记录注册时用户的状态以及修改的原因，例如换猫，换口
    remarks = kwargs.get('remarks')
    status = kwargs.get('status')
    service_type = kwargs.get('service_type')
    lineprofile_id = '2'
    srvprofile_id = srvprofile_dict[kwargs.get('ont_model')]
    api_version = kwargs.get('api_version', 0)
    # 如果force = True， 用于强制换口
    force = kwargs.get('force', False)

    # write log
    logger.info('User {} is using ont_register_func'.format(session['LOGINNAME']))

    # 允许不传入ip， login_name, login_password, 通过device_id来查找数据库完成
    if '' in (ip, login_name, login_password) and device_id:
        device_info = Device.query.filter_by(id=device_id).first()
        ip, login_name, login_password = device_info.ip, device_info.login_name, device_info.login_password

    # telnet olt
    try:
        tlt = Telnet5680T.TelnetDevice(mac, ip, login_name, login_password)
        fsp = tlt.auto_find_onu()
        if fsp:
            logger.debug(fsp)
            f, s, p = fsp.split('/')
            tlt.go_into_interface_mode(fsp)

            try_once = True
            success, ont_id = False, False

            while try_once or force:
                try_once = False
                ont_add_result = tlt.add_ont(p, mac, lineprofile_id, srvprofile_id, ont_model)

                for line in ont_add_result:
                    logger.debug('ont add result {}'.format(line))
                    if re.search(r'ONT MAC is already exist', line):
                        if force:
                            try:
                                # 如果强制换口，则在本OLT上查找对应的MAC
                                this_mac_location = OntStatus.ontLocation(device_id=device_id, mac=mac)

                                # 如果查找对应ONU失败，则返回错误原因
                                if not this_mac_location:
                                    tlt.telnet_close()
                                    return {"status": "fail",
                                            "content": "换口时查找ONU {} 失败，请联系网管处理".format(mac)} if api_version else 6

                                # 如果找到，则fsp及ontid_为onu目前所在的端口位置
                                fsp, ontid_ = this_mac_location[device_id]
                                f_, s_, p_ = fsp.split('/')

                                # 强制删除此ONU
                                release_result = release_ont_func(device_id, f_, s_, p_, ontid_, mac)
                                if not release_result:
                                    logger.warning('Release {} fail'.format(mac))
                                    tlt.telnet_close()
                                    return {"status": "fail",
                                            "content": flash_message['6'] + ', 并且删除失败，请联系网管'} if api_version else 6
                            except Exception as e:
                                tlt.telnet_close()
                                return {"status": "fail", "content": str(e)} if api_version else 6

                    if re.search(r'upper limit', line):
                        logger.warn('ONT {} add fail: The number of ONT in port already reach upper limit'.format(mac))
                        tlt.telnet_close()
                        return {"status": "fail", "content": flash_message['7']} if api_version else 7

                    if re.findall(r'success\s*:\s*(\d+)', line):
                        success = re.findall(r'success\s*:\s*(\d+)', line)[0]
                        force = False
                    elif re.findall(r'ONTID\s*:\s*(\d+)', line):
                        ont_id = re.findall(r'ONTID\s*:\s*(\d+)', line)[0]
                        force = False

            if success and ont_id:
                # write log
                logger.info('ONT register successfully {}. MAC {} fsp {} ontid {}'.format(success, mac, fsp, ont_id))

                eth_port = eth[ont_model]
                cevlan = get_cevlan(device_id, f, s, p, service_type)
                if cevlan:
                    # write log
                    logger.info('Get the cevlan {}'.format(cevlan))

                    # old method just support 1 port onu, not used yet
                    # regist_status = 1 if tlt.ont_port_native_vlan_add(p, ont_id, eth_port, cevlan) else 4

                    add_cevlan_flag = 0
                    for e_port in range(1, int(eth_port) + 1):
                        if tlt.ont_port_native_vlan_add(p, ont_id, str(e_port), cevlan):
                            logger.debug('add ont on {} {} eth {} cevlan {}'.format(p, ont_id, str(e_port), cevlan))
                            add_cevlan_flag += 1

                    logger.debug('add_cevlan_flag: {}'.format(add_cevlan_flag))

                    regist_status = 1 if add_cevlan_flag == int(eth_port) else 4

                    # insert register log into database
                    try:
                        ont_regist_data = OntRegister(f=f, s=s, p=p, mac=mac, cevlan=cevlan, ont_id=ont_id,
                                                      device_id=device_id,
                                                      ont_model=ont_model, regist_status=regist_status,
                                                      username=username,
                                                      user_addr=user_addr, reporter_name=reporter_name,
                                                      reporter_group=reporter_group, regist_operator=register_name,
                                                      remarks=remarks, status=regist_status,
                                                      create_time=time.localtime(), update_time=time.localtime())
                        ins_cevlan = CeVlan(f=f, s=s, p=p, device_id=device_id, cevlan=cevlan, ont_id=ont_id)
                        db.session.add(ins_cevlan)
                        db.session.add(ont_regist_data)
                        db.session.commit()
                        logger.info('Insert the ont register info into db successful')
                        tlt.telnet_close()
                        return {"status": "ok", "content": ont_regist_data.id} if api_version else regist_status
                    except Exception as e:
                        logger.error('Insert the ont register info error {}'.format(e))
                        regist_status = 8
                else:
                    # write log
                    logger.warning('No cevlan found')
                    regist_status = 7

                # 判断是否回滚
                # 如果ont_add成功，但是绑定cevlan失败，则进行回滚
                if regist_status == 4 or regist_status == 7 or regist_status == 8:
                    logger.warning('Start to rollback')
                    regist_status += 100 if release_ont_func(device_id, f, s, p, ont_id, mac) else 200
            else:
                regist_status = 3
                logger.info('Find ONU {}, but cannot add this ONT'.format(mac))
        else:
            regist_status = 2
            logger.info('Cannot find this ONU {}'.format(mac))

        tlt.telnet_close()
        logger.info('The ont register result is {}'.format(regist_status))
        return {"status": "fail", "content": flash_message[str(regist_status)]} if api_version else regist_status
    except Exception as e:
        logger.error('ont_register_func telnet {} error {}'.format(ip, e))
        return {"status": "fail", "content": flash_message['5']} if api_version else 5


def release_ont_func(device_id, f, s, p, ont_id, mac, to_status=None):
    # check the mac info in the interface epon f/s
    # then display ont info p all
    # to get the ont_id and mac relationship
    # if the parameters are right
    # then execute ont delete command

    def _del_db():
        try:
            ont_register_record = \
                OntRegister.query.filter_by(device_id=device_id, f=f, s=s, p=p, ont_id=ont_id, mac=mac).all()
            delete_cevlan_list = []
            if ont_register_record:
                for record in ont_register_record:
                    logger.debug(
                        'The status of OntRegister record id {} is updated to {}'.format(record, str(to_status)))
                    record.status = to_status
                    db.session.add(record)
                    delete_cevlan_list.append(record.cevlan)
                for cevlan in delete_cevlan_list:
                    logger.debug('{} {}'.format(cevlan, type(cevlan)))
                    cevlan_record = CeVlan.query.filter_by(device_id=device_id, f=f, s=s, p=p, ont_id=ont_id,
                                                           cevlan=cevlan).all()
                    if len(cevlan_record) > 0:
                        logger.debug(cevlan_record)
                        for cr in cevlan_record:
                            logger.debug('cevlan to be deleted {}'.format(cr))
                            db.session.delete(cr)
                    else:
                        logger.warning('no cevlan selected to delete for ont {}'.format(mac))
                db.session.commit()
            else:
                logger.warning('no cevlan selected to delete for ont {}'.format(mac))

            logger.info('Cevlan related is deleted in database. The status of the ont is updated to 998.')
            return True
        except Exception as e:
            logger.error('write db error {}'.format(e))
            return False

    device_info = Device.query.filter_by(id=device_id, status='1').first()
    if not device_info:
        flash('此设备无效，不能在线删除')
        return False
    ip = device_info.ip
    username = device_info.login_name
    password = device_info.login_password

    logger.info('release_ont_func_log: User {} trying to release ont {} on device {} - {}'
                .format(session['LOGINNAME'], mac, device_id, ip))

    to_status = 998 if to_status is None else to_status

    # telnet olt
    try:
        tlt = Telnet5680T.TelnetDevice('', ip, username, password)
        fsp = f + '/' + s + '/' + p
        tlt.go_into_interface_mode(fsp)
        ont_info = tlt.display_ont_info(p)
        find_flag = False
        for line in ont_info:
            if re.search(mac.upper(), line):
                logger.debug('filtered line {}'.format(line))
                find_flag = True
                break
        if find_flag:
            logger.info('ont {} find on device {} {}/{}/{} {}'.format(mac, device_id, f, s, p, ont_id))
            release_result = tlt.release_ont(p, ont_id)
            if release_result["status"]:
                return _del_db()
            elif release_result['content'] == 'This configured object has some service virtual ports':
                tlt.quit()
                int_service_port = tlt.display_service_port_in_interface(fsp)
                for isp in int_service_port:
                    if re.search(r'\s+2002\s+common.*\s+' + str(ont_id) + '\s+', isp):
                        index = re.findall(r'\s*(\d+)\s+2002', isp)[0]
                        tlt.undo_service_port(index)
                        tlt.go_into_interface_mode(fsp)
                        release_result = tlt.release_ont(p, ont_id)
                        if release_result["status"]:
                            return _del_db()
                        else:
                            return False
        else:
            logger.warning('ont {} is not registered on device {} {}/{}/{} {}'.format(mac, device_id, f, s, p, ont_id))
            flash('未找到注册光猫，不可删除')
            return False
    except Exception as e:
        logger.error('connect timeout when release ont on {} for {}'.format(ip, e))
        return False


def ont_autofind_func(machine_room='', mac='', device_list=''):
    device_list = get_device_info(machine_room) if machine_room else Device.query.filter_by(id=device_list,
                                                                                            status=1).all()
    autofind_result = defaultdict(list)
    if device_list:
        for device in device_list:
            logger.debug('telnet device {} {}'.format(device.device_name, device.ip))
            try:
                tlt = Telnet5680T.TelnetDevice(mac, device.ip, device.login_name, device.login_password)
                if not mac:
                    autofind_result[device.device_name] = tlt.display_ont_autofind_all()
                else:
                    autofind_result[device.id] = tlt.auto_find_onu()
                tlt.telnet_close()
            except Exception as e:
                logger.error(e)
                return False
    if mac:
        check_result = list(set(autofind_result.values()))
        if len(check_result) == 1 and check_result[0] is False:
            return False
    return autofind_result if device_list else False


def olt_temp_func(machine_room):
    checktemp_result = defaultdict(list)
    for mr in machine_room:
        device_list = get_device_info(mr)
        if device_list:
            for device in device_list:
                try:
                    tlt = Telnet5680T.TelnetDevice('', device.ip, device.login_name, device.login_password)
                    checktemp_result[device.device_name] = tlt.check_temperature()
                    tlt.telnet_close()
                except Exception as e:
                    logger.error('cannot telnet this device to get board\'s temperature')
                    return False
    return checktemp_result


def sync_cevlan(device_id):
    """
    cevlan must uniq in outside vlan in one OLT device
    :param kwargs:  1: just device id 0: ip, login_name, login_password
    :return:
    """
    device_info = Device.query.filter_by(id=device_id).first()
    if device_info:
        ip = device_info.ip
        username = device_info.login_name
        password = device_info.login_password
        logger.info('sync cevlan on device {} {}'.format(device_info.device_name, ip))

        # telnet olt
        try:
            tlt = Telnet5680T.TelnetDevice('', ip, username, password)
            slot_list = [line.strip().split()[0] for line in tlt.check_board_info()]
            logger.debug('the board info {}'.format(slot_list))
            all_cevlan = []
            f = '0'
            p = '0'
            for s in slot_list:
                fsp = f + '/' + s + '/' + p
                tlt.go_into_interface_mode(fsp)
                epon_cur_conf = tlt.display_epon_current()
                cevlan_list = []
                for line in epon_cur_conf:
                    if re.search(r'native-vlan', line):
                        logger.debug('Get the cevlan config {}'.format(line))
                        cevlan_list.append(
                            re.findall(r'ont\s+port\s+native-vlan\s+(\d+)\s+(\d+)\s+eth\s+\d+\s+vlan\s+(\d+)', line)[0])

                if len(cevlan_list) > 0:
                    all_cevlan.extend(cevlan_list)
                    for e in cevlan_list:
                        exist_cevlan = \
                            CeVlan.query.filter_by(device_id=device_id, f=f, s=s, p=e[0], ont_id=e[1]).first()
                        if exist_cevlan:
                            exist_cevlan.cevlan = e[2]
                            db.session.add(exist_cevlan)
                        else:
                            ins_cevlan = CeVlan(f=f, s=s, p=e[0], ont_id=e[1], device_id=device_id, cevlan=e[2])
                            db.session.add(ins_cevlan)
                    db.session.commit()
                    logger.info('device %s sync cevlan finished' % device_id)
                else:
                    cevlan_list = ('', '', '2')
                    all_cevlan.extend(cevlan_list)
            tlt.telnet_close()
        except Exception as e:
            logger.error('connect error when sync cevlan'.format(e))
    else:
        logger.warning('Device select by {} is not exist'.format(session['LOGINNAME']))


def sync_service_port(*args):
    """
    sync the service port info
    :param device_id:
    :return: no return
    """
    logger.debug('sync_service_port'.format(args))
    device_id = args[0]
    device_info = Device.query.filter_by(id=device_id).first()
    if device_info:
        ip = device_info.ip
        username = device_info.login_name
        password = device_info.login_password
        logger.info('sync service port on device {} {}'
                    .format(device_info.device_name, ip))

        # telnet olt
        try:
            tlt = Telnet5680T.TelnetDevice('', ip, username, password)
            service_port_all = tlt.display_service_port_all()
            delete_serviceport_record = ServicePort.query.filter_by(device_id=device_id).all()
            logger.info('start to delete the origin service port record')
            tlt.telnet_close()
            try:
                # delete the old record
                for record in delete_serviceport_record:
                    logger.debug(record)
                    db.session.delete(record)
                db.session.commit()

                for line in service_port_all:
                    if re.search(r'QinQ', line):
                        line = line.strip('')
                        logger.debug(line)
                        if re.search(r'\'$', line):
                            line = line.strip('\'')
                        if re.search(r'\"$', line):
                            line = line.strip('\"')
                        pevlan, f, s, p = re.findall(r'\d+\s+(\d+)\s+QinQ\s+epon\s+(\d+)/(\d+)\s*/(\d+)', line)[0]
                        cevlan_start, cevlan_stop = re.findall(r'vlan\s+(\d+)\-*(\d*)', line)[0]
                        cevlan_range = cevlan_start + '-' + cevlan_stop
                        port_status = re.findall(r'\s+(\w+)$', line)[0]
                        logger.debug('Data to be insert: '
                                     'device_id {}, {}/{}/{}, pevlan:{}, cevlan_range:{}, port_status:{}'
                                     .format(device_id, f, s, p, pevlan, cevlan_range, port_status))
                        ins_service_port = ServicePort(device_id=device_id, f=f, s=s, p=p,
                                                       pevlan=pevlan,
                                                       cevlan_range=cevlan_range,
                                                       port_status=port_status,
                                                       update_time=time.localtime())
                        db.session.add(ins_service_port)
                try:
                    db.session.commit()
                    logger.info('device %s sync service port finish' % device_id)
                    logger.info('start to sync table on device {}: PEVLAN'.format(device_id))
                    for serviceport in ServicePort.query.filter_by(device_id=device_id).all():
                        if not PeVlan.query.filter_by(device_id=serviceport.device_id,
                                                      pevlan=serviceport.pevlan).first():
                            logger.debug('service port to be sync to pevlan: {} {} '.format(serviceport.device_id,
                                                                                            serviceport.pevlan))

                            ins_pevlan = \
                                PeVlan(device_id=serviceport.device_id, pevlan=serviceport.pevlan,
                                       service_type=1, update_time=time.localtime())
                            db.session.add(ins_pevlan)
                            db.session.commit()
                    logger.info('device {} sync to pevlan table finished'.format(device_id))
                    return True
                except Exception as e:
                    logger.info('device {} sync service port fail {}'.format(device_id, e))
                    return False
            except Exception as e:
                logger.error('delete origin service port record error {}'.format(e))
                return False
        except SystemExit:
            return False
    else:
        logger.warning('Device {} selected by {} is not exist'.format(device_id, session['LOGINNAME']))
        return False


def sync_ont_detail(id):
    logger.info("start AnalysisONT")
    AnalysisONT(id)
    time.sleep(10)

    logger.info("start update_ont_info")
    update_ont_info(id)
    time.sleep(10)

    logger.info("start ont_learned_by_mac")
    ont_learned_by_mac(id)
    time.sleep(10)


def save_config(device_id):
    device_info = Device.query.filter_by(id=device_id).first()
    if device_info:
        ip = device_info.ip
        username = device_info.login_name
        password = device_info.login_password
        logger.info('save config on device {} {}'.format(device_info.device_name, ip))

        # telnet olt
        try:
            tlt = Telnet5680T.TelnetDevice('', ip, username, password)
            save_result = tlt.save_config()
            time.sleep(1)
            tlt.telnet_close()
            logger.info('save result {}'.format(save_result))
        except Exception as e:
            logger.warning('Not saved on device {}'.format(device_id, e))
    else:
        logger.warning('the device {} is not exist'.format(device_id))


def manual_sync_func(func_id, device_id_list):
    func = dict([('1', sync_cevlan),
                 ('2', sync_service_port),
                 ('3', AnalysisONT),
                 ('4', update_ont_info),
                 ('5', ont_learned_by_mac),
                 ('6', sync_ont_detail),
                 ('7', save_config),
                 ('8', get_ont_detail)])

    t = []
    for index, device in enumerate(device_id_list):
        logger.info('do {} on {}'.format(func[func_id], device))
        t.append(index)
        t[index] = threading.Thread(target=func[func_id], args=(device,))
        t[index].start()

    # 目前考虑异步模式
    # for th in t:
    #    th.join()

    return True


def discover_alter_interface_func(source_machine_room, destination_machine_room):
    print('star to alter interface func')
    logger.info('star to alter interface func')

    # 用来存放所有目标机房自动发现的ONU信息, 以设备名称为key
    autofind_result = defaultdict(list)

    #
    dst_src_list = {}
    alter_matched_onu_flag = False
    for dst_room in destination_machine_room:
        # get the destination machine room information
        device_list = get_device_info(dst_room)

        for device in device_list:
            logger.debug('telnet device {} {}'.format(device.device_name, device.ip))
            try:
                tlt = Telnet5680T.TelnetDevice('', device.ip, device.login_name, device.login_password)
                autofind_result[device.device_name] = tlt.display_ont_autofind_all()
                tlt.telnet_close()
            except Exception as e:
                logger.error(e)
                return False

        # 用来查找目标设备上自动发现的fsp 及其所属的onu mac
        logger.debug('start to get the fsp -- mac')
        for key, value in autofind_result.items():
            flag = False
            dfsp_mac = defaultdict(list)
            fsp_temp = ()
            for i in value:
                i = i.replace(' ', '')
                if re.search(r'F\/S\/P', str(i)) and flag is False:
                    fsp = re.findall(r'(\d+)\s*/\s*(\d+)\s*/\s*(\d+)', str(i))[0]
                    logger.debug('find f/s/p {}'.format(fsp))

                    if fsp not in dfsp_mac.keys():
                        dfsp_mac[(device.id, fsp[0], fsp[1], fsp[2])] = []

                    # 标记找到一个FSP, 接下来查找对应的MAC
                    flag = True
                    fsp_temp = (device.id, fsp[0], fsp[1], fsp[2])

                elif flag is True and len(fsp_temp) > 0 and re.search(r'Mac|MAC', str(i)):
                    mac_temp = re.findall(r'([0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4})', str(i))[0]
                    logger.debug('the mac is {} '.format(mac_temp))
                    dfsp_mac[fsp_temp].append(mac_temp)
                    flag = False

            # write log
            for k, v in dfsp_mac.items():
                logger.debug(k)
                logger.debug(v)

    if len(dfsp_mac) <= 0:
        return 'no autofind'

    # get the source machine room information
    logger.debug('get the source machine room information')
    fsp_delete_list = []
    ont_delete_list = []
    abnormal_info = False
    for s_m_r in source_machine_room:
        s_d = get_device_info(s_m_r)
        for d in s_d:
            logger.debug('source device id {}'.format(d))

            try:
                # 获取对应设备的所有ONT信息
                get_ont_detail(d.id)
            except Exception as e:
                abnormal_info = 'Get the ONT detail on device {} fail'.format(d)
                logger.error(abnormal_info)
                return abnormal_info

            for dest_dfsp, mac in dfsp_mac.items():
                logger.debug(mac[0])
                ont_info = \
                    ONTDetail.query.filter(ONTDetail.device_id.__eq__(d.id),
                                           ONTDetail.mac.__eq__(str(mac[0]))).first()
                if ont_info:
                    if dest_dfsp != (d.id, ont_info.f, ont_info.s, ont_info.p):
                        fsp_delete_list. \
                            append(((str(d.id), ont_info.f, ont_info.s, ont_info.p),
                                    (str(dest_dfsp[0]), dest_dfsp[1], dest_dfsp[2], dest_dfsp[3])))
                        src_dfsp = (d.id, ont_info.f, ont_info.s, ont_info.p)

                        # matched ont
                        ont_delete_list.append((str(d.id),
                                                ont_info.f,
                                                ont_info.s,
                                                ont_info.p,
                                                ont_info.ont_id,
                                                (str(dest_dfsp[0]), dest_dfsp[1], dest_dfsp[2], dest_dfsp[3]),
                                                ont_info.mac))

                        if src_dfsp not in dst_src_list.keys():
                            dst_src_list[src_dfsp] = dest_dfsp
                        else:
                            if dst_src_list.get[src_dfsp] != dest_dfsp:
                                logger.warning('one src port to multi dst port, '
                                               'so the program just could alter matched onu')
                                alter_matched_onu_flag = True
                    else:
                        abnormal_info = 'the destination fsp eq source fsp'
                        logger.warning('the destination fsp eq source fsp')

    if len(fsp_delete_list) <= 0:
        return abnormal_info if abnormal_info else 'not find ont info in dst machine room'

    if not alter_matched_onu_flag:
        fsp_delete_target = set(fsp_delete_list)
        logger.debug(fsp_delete_target)
        logger.debug('start to get the ont info in interface {}'.format(fsp_delete_target))
        all_ont_tobe_deleted = defaultdict(list)
        for src_dst_dfsp in fsp_delete_target:
            dfsp = src_dst_dfsp[0]
            ont_on_interface = \
                ONTDetail.query.filter(ONTDetail.device_id.__eq__(dfsp[0]),
                                       ONTDetail.f.__eq__(dfsp[1]),
                                       ONTDetail.s.__eq__(dfsp[2]),
                                       ONTDetail.p.__eq__(dfsp[3])).all()
            all_ont_tobe_deleted[src_dst_dfsp] = [(field.device_id,
                                                   field.f,
                                                   field.s,
                                                   field.p,
                                                   field.ont_id,
                                                   field.mac,
                                                   field.line_profile_id,
                                                   field.server_profile_id)
                                                  for field in ont_on_interface]

        # write log.
        for kk, vv in all_ont_tobe_deleted.items():
            logger.debug(kk)
            for vvv in vv:
                logger.debug(vvv)
        logger.debug('ont matched on dst device {}'.format(ont_delete_list))

        return [alter_matched_onu_flag, fsp_delete_target, all_ont_tobe_deleted, ont_delete_list]
    else:
        return [alter_matched_onu_flag, '', '', ont_delete_list]


def ont_modify_func(device_id, f, s, p, ontid, mac, force=False):
    device_info = Device.query.filter_by(id=device_id).first()
    if device_info:
        ip = device_info.ip
        username = device_info.login_name
        password = device_info.login_password
        logger.info('sync cevlan on device {} {}'.format(device_info.device_name, ip))

        # telnet olt
        try:
            tlt = Telnet5680T.TelnetDevice('', ip, username, password)
            tlt.go_into_interface_mode('/'.join([f, s, p]))
            modify_result = tlt.ont_modify(p, ontid, mac, force=force)
            tlt.telnet_close()
            return {"status": "ok", "content": "更换光猫成功, 请确认用户上网正常"} if modify_result else {"status": "fail",
                                                                                           "content": "更换光猫失败"}
        except Exception as e:
            logger.error(e)
            return {"status": "fail", "content": "更换光猫操作异常，请联系值班网管"}
    else:
        return {"status": "fail", "content": "更换光猫操作异常, 未找到设备信息, 请联系值班网管"}


def change_service(olt_name=None, ports_name=None, service_type='4', mac=None):
    """

    :param olt_name:
    :param ports_name:
    :param service_type:
    :param mac:
    :return:
    """
    logger.debug("start to change service")
    logger.debug(str(olt_name) + ' ' + str(mac) + ' ' + str(ports_name))
    service_type_dict = {'1': 'founderbn', '4': 'unicom'}
    # 允许不传入ip， login_name, login_password, 通过device_id来查找数据库完成

    mac_reg = re.compile(r'[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}')
    device_info = Device.query.filter_by(id=olt_name).first()
    ip, login_name, login_password = device_info.ip, device_info.login_name, device_info.login_password

    row_raw = {'device_id': olt_name,
               'ont_model': '1',
               'number': '',
               'username': service_type_dict[service_type],
               'user_addr': service_type_dict[service_type],
               'reporter_group': 'r2d2',
               'reporter_name': 'r2d2',
               'register_name': 'r2d2',
               'remarks': service_type_dict[service_type],
               'service_type': service_type}

    logger.debug(str(row_raw))

    # telnet olt
    try:
        tlt = Telnet5680T.TelnetDevice('', ip, login_name, login_password)
        logger.debug(str(mac) + ' ' + str(ports_name))
        if mac is None and ports_name is not None:
            for port in ports_name:
                dst_ont_list = []
                f, s, p = port.split('/')
                tlt.go_into_interface_mode(port)
                onts_info_list = tlt.display_ont_info(p)
                epon_cur_conf = tlt.display_epon_current()
                cevlan_dict = defaultdict(dict)
                for line in epon_cur_conf:
                    if re.search(r'native-vlan', line):
                        logger.debug('Get the cevlan config {}'.format(line))
                        port, ontid, cevlan = re.findall(r'ont\s+port\s+native-vlan\s+(\d)+\s+(\d+)\s+eth\s+\d+\s+vlan\s+(\d+)', line)[0]
                        cevlan_dict[port][ontid] = cevlan
                        logger.debug(port + ' ' + ontid + ' ' + cevlan)
                        logger.debug(str(cevlan_dict))

                for line in onts_info_list:
                    if re.search(mac_reg, line):
                        ont_id, mac = re.findall('(\d+)\s+([0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})', line)[0]
                        logger.debug(p + ' ' + ont_id + ' ' + mac)
                        now_vlan = cevlan_dict[p][ont_id]
                        logger.debug("now the cevlan is {} type is ".format(now_vlan, type(now_vlan)))
                        if int(now_vlan) < 2094:
                            row_tmp = row_raw.copy()
                            row_tmp['f'] = f
                            row_tmp['s'] = s
                            row_tmp['p'] = p
                            row_tmp['mac'] = mac
                            row_tmp['ont_id'] = ont_id
                            dst_ont_list.append(row_tmp)

                for r in dst_ont_list:
                    result = ont_add_native_vlan(tlt, **r)
                    logger.debug(result)
                tlt.quit()
        elif mac is not None and ports_name is None:
            logger.debug('change for a mac')
            mac = mac['mac']
            f, s, p = mac['info'][0].split('/')
            ont_id = mac['info'][1]
            row_tmp = row_raw.copy()
            row_tmp['f'] = f
            row_tmp['s'] = s
            row_tmp['p'] = p
            row_tmp['mac'] = mac
            row_tmp['ont_id'] = ont_id
            result = ont_add_native_vlan(tlt, **row_tmp)
            logger.debug(result)

        tlt.telnet_close()
        return {'status': 'true', 'content': '变更服务成功'}
    except Exception as e:
        logger.error(str(e))
        return {'status': 'false', 'content': '变更服务失败'}


def set_unicom_service_port(device_id):
    device_info = Device.query.filter_by(id=device_id).first()

    if not device_info.status:
        logger.warning(
            'Status %s. This device is not available in func \'set_unicom_service_port\'' % device_info.status)
        exit()

    tlnt = Telnet5680T.TelnetDevice(mac='', host=device_info.ip, username=device_info.login_name,
                                    password=device_info.login_password)

    # get the number of boards
    board_id_list = [line.strip().split()[0] for line in tlnt.check_board_info()]
    logger.debug(board_id_list)

    unicom_pevlan = list(set([p.pevlan for p in PeVlan.query.filter_by(device_id=device_id, service_type='4').all()]))[
        0]

    service_port_exist = [sp.s + '/' + sp.p for sp in
                          ServicePort.query.filter_by(device_id=device_id, pevlan=unicom_pevlan).all()]

    logger.debug('find the unicom_pevlan is {}'.format(unicom_pevlan))
    logger.debug('the port which has unicom pevlan is {}'.format(str(service_port_exist)))

    for bid in board_id_list:
        ont_list, port_list = tlnt.check_board_info(slot=bid)
        logger.debug('the slot {} has ports {}'.format(bid, str(port_list)))
        for port in port_list:
            if bid + '/' + port not in service_port_exist:
                logger.debug(port)
                result = tlnt.add_service_port(bid + '/' + port, unicom_pevlan)
                logger.debug('add service port result is {}'.format(result))
