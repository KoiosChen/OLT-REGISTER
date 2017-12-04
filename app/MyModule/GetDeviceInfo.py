from ..models import Device
from .. import logger


def get_device_info(machine_room_id):
    """
    :param machine_room_id:
    :return:
    """
    device_info = Device.query.filter_by(machine_room_id=machine_room_id, status=1).all()
    logger.debug('device list: {} '.format(device_info))
    return device_info if device_info else False
