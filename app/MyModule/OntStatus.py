from ..models import ontinfo_translate, MachineRoom, Device
from .FindByMac import FindByMac
from .GetDeviceInfo import get_device_info
from .. import logger
from . import GetDeviceInfo
import re


def ont_status(mac, machine_room, level='verbose', device=None):
    # machine_room 可以传入机房ID， 也可以传入机房名称
    if device is None and re.search('\d+', machine_room):
        device_list = GetDeviceInfo.get_device_info(machine_room)
    elif device is None:
        device_list = GetDeviceInfo.get_device_info(MachineRoom.query.filter_by(name=machine_room).first().id)
    elif device is not None:
        device_list = Device.query.filter_by(id=device).all()

    if device_list:
        # 解决一个机房下有多个OLT的问题
        device_status = len(device_list)
        for device in device_list:
            if device.status == 2:
                device_status -= 1
                continue
            optical, onuinfo, downcause, ontversion = \
                FindByMac(mac, device.ip, device.login_name, device.login_password, level=level)
            if optical:
                break
            else:
                continue

        if not device_status:
            logger.info('This device is not supported')
            return {'status': 'false', 'content': '此设备不支持,请联系网管'}

        if not optical and device_status:
            logger.info('ONU {} is not found in machine room {}'.format(mac, machine_room))
            return {'status': 'false', 'content': '未找到光猫,请检查线路或联系网管'}
    else:
        logger.info('Machine room {} does not have devices'.format(machine_room))
        return {'status': 'false', 'content': '未找到对应机房.'}

    r = []
    if optical:

        for i in onuinfo:
            if re.search(r'F/S/P|ONT\-ID|Control flag|Run state|Description|Last|Line|Service profile', str(i)):
                if i.strip()[:-1]:
                    r.append(i.strip())

        for i in ontversion:
            if re.search(r'Vendor-ID|OUI|ONT', str(i)):
                if i.strip()[:-1]:
                    r.append(i.strip())

        for i in optical:
            if re.search(r'Rx optical power|Voltage|Temperature\(C\)|OLT Rx ONT optical power', str(i)):
                if i.strip()[:-1]:
                    r.append(i.strip())

        for i in downcause:
            if not re.search(r'display|More|Q|config-if-epon|^b\'', str(i)):
                if i.strip()[:-1]:
                    r.append(i.strip())

    # 把部分关键字转换成中文
    translated = []
    for info in r:
        if re.search(r':', info):
            for key, value in ontinfo_translate.items():
                if key in info:
                    info = info.replace(key, value)

        translated.append(info)

    return {'status': 'true', 'content': translated}


def ontLocation(device_id='', machine_room='', mac=''):
    """

    :param device_id: 某台设备ID
    :param machine_room:
    :param mac:
    :return:
    """
    device_list = get_device_info(machine_room) if machine_room else Device.query.filter_by(id=device_id).all()
    if device_list:
        for device in device_list:
            logger.debug('telnet device {} {}'.format(device.device_name, device.ip))
            try:
                fsp, ontid, _, _ = FindByMac(mac, device.ip, device.login_name, device.login_password, level='fsp')
                if fsp and ontid:
                    return {device_id: (fsp, ontid)}
                else:
                    return False
            except Exception as e:
                logger.error(e)
                return False

    return False