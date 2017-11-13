#!/usr/bin/env python
import os
from app import create_app, db
from app.models import User, Role, MachineRoom, Device, ONTDetail, ServicePort, PeVlan
from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand
from app.my_func import test, GetBASEInfo, ont_learned_by_mac, start_func, sync_cevlan, sync_service_port, \
    get_ont_detail, manual_sync_func
from app.Tools import AuditRegistRecord


app = create_app(os.getenv('FLASK_CONFIG') or 'default')
manager = Manager(app)
migrate = Migrate(app, db)


def make_shell_context():
    return dict(app=app, db=db, User=User, Role=Role, MachineRoom=MachineRoom, Device=Device, PeVlan=PeVlan,
                ONTDetail=ONTDetail, test=test, GetBASEInfo=GetBASEInfo, ont_learned_by_mac=ont_learned_by_mac,
                start=start_func, sync_cevlan=sync_cevlan, ServicePort=ServicePort, sync_service_port=sync_service_port,
                get_ont_detail=get_ont_detail, manual=manual_sync_func, AuditRegistRecord=AuditRegistRecord)


manager.add_command("shell", Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)

if __name__ == '__main__':
    manager.run()
