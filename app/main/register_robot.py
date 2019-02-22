from flask import redirect, session, url_for, render_template, request, jsonify
from flask_login import login_required
from ..models import ServicePort, Permission, Device
from ..decorators import admin_required, permission_required
from ..my_func import get_machine_room_by_area
from .forms import AutoRegister
from . import main
import uuid
import time
import json
from .. import db, logger, scheduler
from datetime import datetime
from datetime import timedelta


def do_autoregister(olt_id, ports):
    logger.debug(olt_id)
    logger.debug(ports)


@main.route('/register_robot', methods=['GET'])
@login_required
@permission_required(Permission.ADMINISTER)
def register_robot():
    form = AutoRegister()
    form.machine_room.choices = get_machine_room_by_area(session.get('permit_machine_room'))
    form.olt_name.choices = [(row.id, row.device_name) for row in Device.query.filter_by(status=1).all()]
    form.port.choices = [('/'.join([row.f, row.s, row.p]), str(row.device_id) + ' ' + '/'.join([row.f, row.s, row.p]))
                         for row in ServicePort.query.all()]
    if request.method == 'GET':
        return render_template('register_robot.html', form=form)
    return redirect(url_for('register_robot'))


@main.route('/_get_olt/')
@login_required
@permission_required(Permission.ADMINISTER)
def _get_olt():
    machine_room = request.args.get('machine_room', '01', type=str)
    olts = [(row.id, row.device_name) for row in Device.query.filter_by(machine_room_id=machine_room, status=1).all()]
    return jsonify(olts)


@main.route('/_get_ports/')
@login_required
@permission_required(Permission.ADMINISTER)
def _get_ports():
    olt_name = request.args.get('olt_name', '01', type=str)
    ports = [('/'.join([row.f, row.s, row.p]), str(row.device_id) + ' ' + '/'.join([row.f, row.s, row.p])) for row in
             ServicePort.query.filter_by(device_id=olt_name).all()]
    return jsonify(ports)


@main.route('/add_scheduler', methods=['POST'])
@login_required
@permission_required(Permission.ADMINISTER)
def _add_scheduler():
    data = request.json
    olt_name = data.get('olt_name')
    ports_name = data.get('ports_name')
    scheduler_name = data.get('scheduler')
    logger.debug("{} {} {}".format(olt_name, ports_name, scheduler_name))
    interval = 300
    job = {'id': str(uuid.uuid1()),
           'func': 'do_autoregister',
           'args': (olt_name, ports_name)}
    result = scheduler.add_job(id=job['id'],
                               func=__name__ + ':' + job['func'],
                               args=job['args'],
                               start_date=datetime.now(),
                               end_date=datetime.now() + timedelta(minutes=int(scheduler_name)),
                               trigger='interval',
                               seconds=interval)
    logger.debug(result)
    return jsonify({"result": str(result), "status": "ok"})
