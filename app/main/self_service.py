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
from ..MyModule.OntStatus import ont_status, ontLocation
from ..MyModule.GetWorkorderInfo import *


@main.route('/self_ont_delete', methods=['GET'])
@login_required
@permission_required(Permission.COMMENT)
def self_ont_delete():
    form = SelfDelete()
    form.machine_room.choices = get_machine_room_by_area(session.get('permit_machine_room'))

    return render_template('self_ont_delete.html', form=form)


@main.route('/do_delete', methods=['POST'])
@login_required
@permission_required(Permission.COMMENT)
def do_delete():
    data = request.json
    machine_room = data.get('machine_room')
    mac = data.get('mac')

    try:
        find_result = ontLocation(machine_room=machine_room, mac=mac)
        logger.debug(find_result)
        if find_result:
            for device_id, port_ontid in find_result.items():
                f, s, p = port_ontid[0].split('/')
                if release_ont_func(device_id, f, s, p, port_ontid[1], mac):
                    return jsonify({"result": '删除光猫成功，设备编号{}, 端口{}, ONTID {}, MAC {}'.format(device_id, port_ontid[0],
                                                                                             port_ontid[1],
                                                                                             mac), "status": "ok"})
        else:
            return jsonify({"result": "未找到对应ONT，删除失败", "status": "false"})
    except Exception as e:
        logger.error(e)
        return jsonify({"result": "未找到对应ONT，删除失败", "status": "false"})
