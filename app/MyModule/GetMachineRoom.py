from ..models import MachineRoom
from .. import logger
from flask import session


def get_machine_room_by_area(permit_machine_room):
    logger.debug('get machine room param: {}'.format(permit_machine_room))
    logger.debug('the session id is {}'.format(session.sid))
    if not permit_machine_room:
        permit_machine_room = '0x0'
    return [(str(k.id), k.name)
            for k in MachineRoom.query.filter(MachineRoom.status != 0).all()
            if int(k.permit_value, 16) & int(permit_machine_room, 16) == int(k.permit_value, 16)]