from .. import logger
from flask import session
from ..telnet_device import Telnet5680T


def FindByMac(mac, ip, username, password, level='base'):
    logger.info('User {} is using FindByMac mac:{}, ip:{}'.format(session['LOGINNAME'], mac, ip))
    try:
        tlt = Telnet5680T.TelnetDevice(mac, ip, username, password)
        fsp, ont_id, result = tlt.find_by_mac(mac)
    except Exception as e:
        logger.error(e)
        return False, False, False, False

    if level == 'verbose':
        if fsp:
            tlt.go_into_interface_mode(fsp)
            p = fsp.split('/')[2]
            optical = tlt.check_optical_info(p, id=ont_id)
            register_info = tlt.check_register_info(p, id=ont_id)
            ont_version = tlt.display_ont_version(port=p, ont_id=ont_id)
            tlt.telnet_close()
            return optical, result, register_info, ont_version
        else:
            tlt.telnet_close()
            return False, False, False, False
    elif level == 'callcenter':
        if fsp:
            tlt.go_into_interface_mode(fsp)
            p = fsp.split('/')[2]
            optical = tlt.check_optical_info(p, id=ont_id)
            register_info = tlt.check_register_info(p, id=ont_id)
            tlt.telnet_close()
            return optical, result, register_info, '_'
        else:
            tlt.telnet_close()
            return False, False, False, False
    elif level == 'fsp':
        if fsp:
            tlt.telnet_close()
            return fsp, ont_id, '_', '_'
        else:
            tlt.telnet_close()
            return False, False, False, False
    elif level == 'optical':
        if fsp:
            tlt.go_into_interface_mode(fsp)
            p = fsp.split('/')[2]
            optical = tlt.check_optical_info(p, id=ont_id)
            tlt.telnet_close()
            return optical, '_', '_', '_'
        else:
            tlt.telnet_close()
            return False, False, False, False
    else:
        return fsp, ont_id, result, '_'
