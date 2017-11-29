from telnet_device import Telnet5680T
from ..models import Device, MachineRoom
from . import GetDeviceInfo
import re


class MA5680T:
    def __init__(self, **kwargs):
        deviceid = kwargs.get('deviceId')
        machineroomid = kwargs.get('machineRoomId')
        machineroomname = kwargs.get('machineRoomName')
        # machine_room 可以传入机房ID， 也可以传入机房名称
        if deviceid is None and machineroomid:
            self.device_list = GetDeviceInfo.get_device_info(machineroomid)
        elif deviceid is None and machineroomid is None and machineroomname:
            self.device_list = GetDeviceInfo.get_device_info(MachineRoom.query.filter_by(name=machineroomname).first().id)
        elif deviceid is not None:
            self.device_list = Device.query.filter_by(id=deviceid).all()


    def telnet_ma5680t(self, device_info):
        self.login_handle = None
        pass