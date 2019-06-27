from flask import redirect, session, url_for, render_template, request, jsonify
from flask_login import login_required
from ..models import ServicePort, Permission, Device
from ..decorators import admin_required, permission_required
from ..my_func import get_machine_room_by_area, change_service, do_autoregister
from .forms import AutoRegister
from . import main
import uuid
import time
import json
from .. import db, logger, scheduler, redis_db
from datetime import datetime
from datetime import timedelta



@main.route('/register_robot', methods=['GET'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def register_robot():
    form = AutoRegister()
    form.machine_room.choices = get_machine_room_by_area(session.get('permit_machine_room'))
    form.olt_name.choices = [(row.id, row.device_name) for row in Device.query.filter_by(status=1).all()]
    fpc = sorted(list(set([('/'.join([row.f, row.s, row.p]), str(row.device_id) + ' ' + '/'.join([row.f, row.s, row.p]))
                           for row in ServicePort.query.all() if int(row.pevlan) in range(700, 760)])))
    form.port.choices = fpc
    if request.method == 'GET':
        return render_template('register_robot.html', form=form)
    return redirect(url_for('register_robot'))


@main.route('/register_new_ont', methods=['GET'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def register_new_ont():
    form = AutoRegister()
    form.machine_room.choices = get_machine_room_by_area(session.get('permit_machine_room'))
    form.olt_name.choices = [(row.id, row.device_name) for row in Device.query.filter_by(status=1).all()]
    fpc = sorted(list(set([('/'.join([row.f, row.s, row.p]), str(row.device_id) + ' ' + '/'.join([row.f, row.s, row.p]))
                           for row in ServicePort.query.all() if int(row.pevlan) in range(700, 760)])))
    form.port.choices = fpc
    return render_template('register_new_ont.html', form=form)


@main.route('/_get_olt/')
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def _get_olt():
    machine_room = request.args.get('machine_room', '01', type=str)
    olts = [(row.id, row.device_name) for row in Device.query.filter_by(machine_room_id=machine_room, status=1).all()]
    return jsonify(olts)


@main.route('/_get_ports/')
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def _get_ports():
    olt_name = request.args.get('olt_name', '01', type=str)
    ports = sorted(list(
        set([('/'.join([row.f, row.s, row.p]), str(row.device_id) + ' ' + '/'.join([row.f, row.s, row.p])) for row in
             ServicePort.query.filter_by(device_id=olt_name).all() if int(row.pevlan) in range(700, 760)])))
    return jsonify(ports)


@main.route('/add_scheduler', methods=['POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def _add_scheduler():
    data = request.json
    olt_name = data.get('olt_name')
    ports_name = data.get('ports_name')
    scheduler_name = data.get('scheduler')
    service_type = data.get('service_type')
    logger.debug("{} {} {}".format(olt_name, ports_name, scheduler_name))
    interval = 300

    uuid_ = str(uuid.uuid1())

    ports_list = []

    for port in ports_name:
        key = json.dumps(('register_new_ont', olt_name, port))
        if not redis_db.exists(key):
            redis_db.set(key, uuid_)
            redis_db.expire(key, int(scheduler_name) * 60 + 600)
            ports_list.append(port)

    if ports_list:
        job = {'id': uuid_,
               'func': 'do_autoregister',
               'args': (olt_name, ports_list, service_type)}
        result = scheduler.add_job(id=job['id'],
                                   func=__name__ + ':' + job['func'],
                                   args=job['args'],
                                   start_date=datetime.now(),
                                   end_date=datetime.now() + timedelta(minutes=int(scheduler_name)),
                                   trigger='interval',
                                   seconds=interval)
        logger.debug(result)

        scheduler.run_job(job['id'])

        return jsonify({"result": str(ports_list) + ' 已加入处理队列', "status": "ok"})
    else:
        return jsonify({"result": '此设备所选端口都在处理中', "status": "fail"})


@main.route('/change_service', methods=['POST'])
@login_required
@permission_required(Permission.NETWORK_MANAGER)
def _change_service():
    data = request.json
    olt_name = data.get('olt_name')
    ports_name = data.get('ports_name')
    service_type = data.get('service_type')
    logger.debug("{} {} {}".format(olt_name, ports_name, service_type))
    result = change_service(olt_name, ports_name, service_type)
    logger.debug(str(result))
    if result['status'] == 'true':
        return jsonify({"result": result['content'], "status": "ok"})
    else:
        return jsonify({"result": result['content'], "status": "false"})
