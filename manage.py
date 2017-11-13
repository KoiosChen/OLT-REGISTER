#!/usr/bin/env python
import os
from app import create_app, db
from app.models import User, Role, MachineRoom, Device, ONTDetail, ServicePort, PeVlan
from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand
from app.my_func import test, GetBASEInfo, ont_learned_by_mac, start_func, sync_cevlan, sync_service_port, \
    get_ont_detail, manual_sync_func
from app.MyModule import SeqPickle, SchedulerControl


app = create_app(os.getenv('FLASK_CONFIG') or 'default')
manager = Manager(app)
migrate = Migrate(app, db)


def make_shell_context():
    return dict(app=app, db=db, User=User, Role=Role, MachineRoom=MachineRoom, Device=Device, PeVlan=PeVlan,
                ONTDetail=ONTDetail, test=test, GetBASEInfo=GetBASEInfo, ont_learned_by_mac=ont_learned_by_mac,
                start=start_func, sync_cevlan=sync_cevlan, ServicePort=ServicePort, sync_service_port=sync_service_port,
                get_ont_detail=get_ont_detail, manual=manual_sync_func)


manager.add_command("shell", Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)


# 检查许可, 如果传入的参数为'1', 则用户若删除licence.pkl文件, 每次重启服务都会产生一个新的licence.pkl文件, 并可以使用7天
init_status = '1'
SeqPickle.checkLicence(init_status)
if init_status == '0':
    # 如果init_status 是0, 表示默认不支持用户使用, 停止所有计划任务
    SchedulerControl.scheduler_pause()
else:
    # 根据数据库配置修改scheduler计划, 用户覆盖默认配置文件中的配置
    SchedulerControl.scheduler_modify()


if __name__ == '__main__':
    manager.run()
