import telnetlib
import time
import re
from flask import session
from .. import logger
from ..MyModule import CheckLicence


class TelnetDevice:
    def __init__(self, mac, host, username, password):
        self.mac = mac
        self.timeout = 3
        self.command_timeout = 0.2
        self.command_interval = 0.2

        try:
            # assert CheckLicence.checkLicence()
            self.tn = telnetlib.Telnet(host, 23, self.timeout)
            self.tn.set_debuglevel(0)
            print('login')
            time.sleep(self.command_interval)

            self.tn.expect([re.compile(b'name:'), ], self.timeout)
            print('input username')

            self.tn.write(username.encode('utf-8') + b'\n')
            time.sleep(self.command_interval)

            self.tn.expect([b'password:', ], self.command_timeout)
            print('input password')

            self.tn.write(password.encode('utf-8') + b'\n\n\n')

            self.tn.expect([b'More', ], self.command_timeout)
            time.sleep(self.command_interval)
            self.tn.write(b'\n')
            time.sleep(self.command_interval)
            self.tn.write(b'\n')
            time.sleep(self.command_interval)
            self.tn.expect([b'>', ], self.command_timeout)
            time.sleep(self.command_interval)
            self.tn.write(b'enable\n')
            time.sleep(self.command_interval)
            self.tn.expect([b'#', ], self.command_timeout)
            time.sleep(self.command_interval)
            self.tn.write(b'conf\n')
            self.tn.expect([re.compile(b'\(config\)\#'), ], self.command_timeout)

            logger.info('Login device {}'.format(host))

        except Exception as e:
            logger.error('Error: {}, telnet {} fail'.format(e, host))

    def get_result(self, stop, patern1='', patern2=''):
        """

        :param stop: the stop flag
        :param patern1: first patern
        :param patern2: second patern
        :return: the first element is all of the result; the second element is the result that matched
        """
        f = True
        result_list = []
        line_result = ''
        while f:
            raw_result = self.tn.read_until(b'More', timeout=2)
            str_result = str(raw_result)
            result = str_result.split('\\r\\n')
            for i in result:
                # This if ... else ... is used for page tuning and break the while
                if re.search(r'vl\'', str(i)):
                    print(i)
                if re.search(r'More', str(i)):
                    self.tn.write(b'\t')
                    time.sleep(self.command_interval)
                elif re.search(stop, str(i)) and not re.search(r'display', str(i)):
                    f = False

                # This if ... else ... is used for tuning output format
                if re.search(r'\\x1b\[37D', str(i)):
                    tmp = [l for l in str(i).split('\\x1b[37D')]
                    for context in tmp:
                        result_list.append(context)
                else:
                    result_list.append(i)

        for line in result_list:
            if re.search(patern1, str(line)) and re.search(patern2, str(line)):
                line_result = line
                break
        return result_list, line_result

    def get_current(self, stop, patern1='', patern2=''):
        f = True
        while f:
            result = str(self.tn.read_until(b'More', timeout=2)).split('\\r\\n')
            for i in result:
                # This if ... else ... is used for page tuning and break the while
                if re.search(r'More', str(i)):
                    self.tn.write(b'\t')
                    time.sleep(self.command_interval)
                elif re.search(stop, str(i)) and not re.search(r'display', str(i)):
                    f = False

                # This if ... else ... is used for tuning output format
                if re.search(r'\\x1b\[37D', str(i)):
                    tmp = [l for l in str(i).split('\\x1b[37D')]
                    for context in tmp:
                        if re.search(patern1, str(context)) and re.search(patern2, str(context)):
                            return context
                else:
                    if re.search(patern1, str(i)) and re.search(patern2, str(i)):
                        return i

    def auto_find_onu(self, mac=None):
        # 提供mac参数
        self.mac = self.mac if mac is None else mac
        logger.debug('display ont autofind all for self.mac {}'.format(self.mac))
        self.tn.write(b'display ont autofind all\n')
        result, __ = self.get_result(stop=r'\(config\)\#', patern1='', patern2='')
        flag = False
        mac_fsp = []
        for i in result:
            i = i.replace(' ', '')
            logger.debug('auto find result {}'.format(i))
            if re.search(r'F\/S\/P', str(i)) and flag is False:
                logger.debug('re %s' % i)
                mac_fsp.append({})
                mac_fsp[len(mac_fsp) - 1]['F/S/P'] = i.split(':')[1]
                flag = True
            # elif flag is True and re.search(r'Mac|MAC', str(i)):
            elif flag and re.search(r'[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}', str(i)):
                find_mac = re.findall(r'([0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4})', str(i))[0]
                logger.debug('find mac {}'.format(find_mac))
                logger.debug('dest mac {}'.format(self.mac))
                if find_mac == self.mac:
                    logger.debug('Get {} on {}'.format(find_mac, mac_fsp[len(mac_fsp) - 1]['F/S/P']))
                    return mac_fsp[len(mac_fsp) - 1]['F/S/P']
                else:
                    flag = False
                    continue
        return False

    def display_ont_autofind_all(self):
        print('display ont autofind all')
        self.tn.write(b'display ont autofind all\n')
        return self.get_result(stop=r'\(config\)\#', patern1='', patern2='')[0]

    def go_into_interface_mode(self, fsp):
        """
        这个方法可以优化,不需要传输fsp, 只需要fs
        :param fsp:
        :return:
        """
        print('interface %s ' % fsp)
        fs = '/'.join(fsp.split('/')[:2])
        self.tn.write(b'int epon ' + fs.encode('utf8') + b'\n')
        time.sleep(self.command_interval)
        if self.tn.expect([b'config-if-epon', ], self.command_timeout):
            return fsp.split('/')[2]
        else:
            return False

    def find_free_loid(self, p):
        """

        :param p: display ont x info to find
        :return: free loid's id
        """
        self.tn.write(b'display ont info ' + p.encode('utf8') + b' all\n')
        time.sleep(self.command_interval)
        __, result = self.get_result(stop='config-if-epon', patern1=r'-----', patern2=r'active')
        if result:
            print(result)
            result = str(result).strip().split()
            print(result)
            # 因为OLT输出格式不同,但是ont_id总是在MAC字段前,所以index空MAC 减1 为ont_id
            point = result.index('--------------') - 1
            print(result[point])
            return result[point]
        else:
            return False

    def display_ont_info(self, p):
        """

        :param p: display ont x info
        :return:
        """
        self.tn.write(b'display ont info ' + p.encode('utf8') + b' all\n')
        time.sleep(self.command_interval)
        return self.get_result(stop='config-if-epon', patern1='', patern2='')[0]

    def display_ont_detail_info(self, p, ontid):
        self.tn.write(b'display ont info ' + p.encode('utf8') + b' ' + ontid.encode('utf8') + b'\n')
        time.sleep(self.command_interval)
        return self.get_result(stop='config-if-epon', patern1='', patern2='')[0]

    def find_loid(self, xr):
        self.tn.write(b'display current-configuration\n')
        time.sleep(self.command_interval)
        result = self.get_current(stop=r'config-if-epon', patern1=r'loid-auth', patern2=xr)
        if result:
            result = str(result).strip().split(' ')
            return result[5].strip("\"")
        else:
            return False

    def display_epon_current(self):
        """
        this display current is used under interface epon mode
        :return:  all of the epon current configuration
        """
        self.tn.write(b'display current-configuration\n')
        time.sleep(self.command_interval)
        return self.get_result(stop=r'config-if-epon', patern1='', patern2='')[0]

    def find_by_mac(self, mac):
        """

        :param mac:
        :return: f/s/p
        """
        print('start to find by mac')
        self.tn.write(b'display ont info by-mac ' + mac.encode('utf8') + b'\n')
        time.sleep(self.command_interval)
        result, line_match = self.get_result(stop=r'\(config\)\#', patern1=r'F/S/P', patern2=':')
        print(line_match)
        if line_match:
            find_result = str(line_match).replace(' ', '').strip('\'').split(':')
        else:
            find_result = False

        ont_id = ''
        for line in result:
            if re.search(r'ONT-ID', line):
                print(line)
                ont_id = str(line).replace(' ', '').strip('\'').split(':')[1]

        return find_result[1] if find_result else False, ont_id, result

    def check_optical_info(self, p, id):
        """

        :param p:  port number
        :param id: ont id
        :return:  return all of the result
        """
        print('check optical info')
        self.tn.write(b'display ont optical-info ' + p.encode('utf8') + b' ' + id.encode('utf8') + b'\n')
        time.sleep(self.command_interval)
        return self.get_result(stop=r'config-if-epon', patern1='', patern2='')[0]

    def release_ont(self, p, id):
        logger.info('User {} is releasing ont on port {} ont_id {}'.format(session['LOGINNAME'], p, id))
        self.tn.write(b'ont delete ' + p.encode('utf8') + b' ' + id.encode('utf8') + b'\n')
        time.sleep(self.command_interval)
        deleted_flag = {"status": False, "content": ""}
        for line in self.get_result(stop=r'config-if-epon', patern1='', patern2='')[0]:
            logger.debug('ont delete result: {}'.format(line))
            if re.search(r'success', line):
                if re.findall(r'success\s*:\s*(\d+)', line)[0] == '1':
                    deleted_flag = {"status": True}
                    logger.info('Release successful')
                    break
                else:
                    logger.info('Release fail')
                    return {"status": False, "content": "success 0"}
            elif re.search(r'This configured object has some service virtual ports', line):
                return {"status": False, "content": "This configured object has some service virtual ports"}
            elif re.search(r'The ONT does not exist', line):
                return {"status": False, "content": "The ONT does not exist"}
        return deleted_flag

    def active_ont(self, p, id):
        print('active ont')
        self.tn.write(b'ont activate ' + p.encode('utf8') + b' ' + id.encode('utf8') + b'\n')
        time.sleep(self.command_interval)
        result, __ = self.get_result(stop=r'config-if-epon', patern1='', patern2='')
        for line in result:
            return False if re.search(r'Failure', str(line)) else True

    def check_register_info(self, p, id):
        print('check register_info')
        self.tn.write(b'display ont register-info ' + p.encode('utf8') + b' ' + id.encode('utf8') + b'\n')
        time.sleep(self.command_interval)
        return self.get_result(stop=r'config-if-epon', patern1='', patern2='')[0]

    def check_board_info(self, board='0', slot=''):
        """

        :param board:
        :param slot:
        :return:  if slot, the second return value is the port number list
        """
        print('display board 0/%s' % slot)
        if slot:
            self.tn.write(b'display board ' + board.encode('utf8') + b'/' + slot.encode('utf8') + b'\n')
        else:
            self.tn.write(b'display board ' + board.encode('utf8') + b'\n')

        time.sleep(self.command_interval)
        result, __ = self.get_result(stop=r'\(config\)\#', patern1='', patern2='')

        if slot:
            # [line.strip().split(',')[0].split()[2] for line in result if re.search(r'total of ONTs', str(line))]
            return [line.strip() for line in result if (re.search(r'[on|off]line', str(line)) and
                                                        not re.search(r'total', str(line))) or re.search(
                r'total of ONTs', str(line))], \
                   [re.findall(r'(\d+)\s*,', line)[0] for line in result if re.search(r'total of ONTs', str(line))]
        else:
            return [line.strip() for line in result if re.search(r'Normal', str(line)) and
                    not re.search(r'GICF|X2CS|GICG', str(line))]

    def check_temperature(self, board='0', slot=''):
        print('display temperature 0/%s' % slot)
        if slot:
            self.tn.write(b'display temperature ' + board.encode('utf8') + b'/' + slot.encode('utf8') + b'\n')
        else:
            self.tn.write(b'display temperature ' + board.encode('utf8') + b'\n')
        time.sleep(self.command_interval)
        result, slot_result = self.get_result(stop=r'\(config\)\#', patern1='temperature', patern2='board')
        if slot:
            if len(slot_result.strip()) < 1:
                return 'Failure: Board does not exist'
            else:
                return slot_result.strip()
        else:
            return [r for r in result if re.search(r'SlotID', r)]

    def display_ont_version(self, **kwargs):
        if kwargs.get('port') and kwargs.get('ont_id'):
            print('display ont version %s %s' % (kwargs.get('port'), kwargs.get('ont_id')))
            self.tn.write(
                b'display ont version ' + kwargs.get('port').encode('utf8') + b' ' + kwargs.get('ont_id').encode(
                    'utf8') + b'\n')
            return self.get_result(stop=r'config-if-epon', patern1='', patern2='')[0]
        else:
            return False

    def display_ont_port_attribute(self, **kwargs):
        """
        获取 ontid native vlan
        :param kwargs:
        :return:
        """
        self.tn.write(
            b'display ont port attribute ' + kwargs.get('portid').encode('utf8') + b' ' + kwargs.get('ontid').encode(
                'utf8') + b'eth 1')
        return self.get_result(stop=r'config-if-epon', patern1='enable', patern2='auto')[1]

    def display_mac_learned_by_ont(self, **kwargs):
        """
        'display ont-learned-mac f/s/p ont_id eth portid vlanid'

        :param kwargs: f, s, p, ontid, portid(optional), vlanid(optional)
        :return: the line within a mac
        """

        portid = kwargs.setdefault('portid', '1')
        fsp = kwargs.get('f') + '/' + kwargs.get('s') + '/' + kwargs.get('p')
        self.tn.write(b'display ont-learned-mac ' + fsp.encode('utf8') + b' ' + kwargs.get('ontid').encode('utf8') +
                      b' ' + b'eth ' + portid.encode('utf8') + b' ' +kwargs.get('vlanid').encode('utf8') + b'\n')
        self.tn.expect([b'<cr>', ], self.command_timeout)
        self.tn.write(b'\n\n')
        return self.get_result(stop=r'\(config\)\#', patern1='', patern2='')[0]

    def go_into_diagnose(self):
        print('diagnose')
        self.tn.write(b'diagnose\n')
        time.sleep(self.command_timeout)

    def display_elabel(self):
        print('display elabel 0')
        self.tn.write(b'display elabel 0\n')
        return self.get_result(stop='SoftwareNum', patern1='', patern2='')[0]

    def add_ont(self, p, mac, lineprofile_id, srvprofile_id, desc):
        """
        Used to add ont to epon interface,
        :param p: the port number
        :param mac: the mac that auto find in the OLT would be added
        :param lineprofile_id: the default id is 2
        :param srvprofile_id:
        :param desc:
        :return: the result
        """
        print('ont add')
        self.tn.write(b'ont add ' + p.encode('utf8') + b' ' +
                      b'mac-auth ' + mac.encode('utf8') + b' ' +
                      b'oam ont-lineprofile-id ' + lineprofile_id.encode('utf8') + b' ' +
                      b'ont-srvprofile-id ' + srvprofile_id.encode('utf8') + b' ' +
                      b'desc ' + desc.encode('utf8') + b'\n')
        return self.get_result(stop=r'config-if-epon', patern1='', patern2='')[0]

    def ont_port_native_vlan_add(self, p, ont_id, eth_port, cevlan):
        """
        bind the native vlan to the ontid
        :param p:
        :param ont_id:
        :param eth_port:
        :param cevlan: equal to native vlan
        :return:
        """
        print('ont port native-vlan p ontid eth eth_port vlan cevlan')
        self.tn.write(b'ont port native-vlan ' + p.encode('utf8') + b' ' +
                      ont_id.encode('utf8') + b' ' +
                      b'eth ' + eth_port.encode('utf8') + b' ' +
                      b'vlan ' + cevlan.encode('utf8') + b'\n')
        return self.get_result(stop=r'config-if-epon', patern1='', patern2='')[0]

    def display_service_port_all(self):
        print('display service port all')
        self.tn.write(b'display service port all\n')
        self.tn.expect([b'<cr>', ], self.command_timeout)
        self.tn.write(b'\n\n')
        return self.get_result(stop=r'\(config\)\#', patern1='', patern2='')[0]

    def display_service_port_in_interface(self, fsp):
        print('display service port fsp')
        self.tn.write(b'display service port ' + fsp.encode('utf8') + b'\n')
        self.tn.expect([b'<cr>', ], self.command_timeout)
        self.tn.write(b'\n\n')
        return self.get_result(stop=r'\(config\)\#', patern1='', patern2='')[0]

    def undo_service_port(self, index):
        print("undo service-port " + str(index))
        self.tn.write(b'undo service-port ' + str(index).encode('utf8') + b'\n')

    def display_port_state(self, port):
        logger.debug('display port state x')
        self.tn.write(b'display port state ' + port.encode('utf8') + b'\n')
        return self.get_result(stop=r'config-if-epon', patern1='', patern2='')[0]

    def ont_modify(self, port, ontid, mac, force=False):
        """
        更换ONU
        :param port:
        :param ontid:
        :return:
        """
        try:
            logger.debug("ont modify {} {} mac {}".format(port, ontid, mac))
            self.tn.write(b'ont modify ' + port.encode('utf8') + b' ' + ontid.encode('utf8') + b' mac ' + mac.encode('utf8') + b'\n')
            time.sleep(1)
            if self.tn.expect([b'registered', ], self.command_timeout):
                if force:
                    self.tn.expect([b'[n]:', ], self.command_interval)
                    self.tn.write(b'y\n')
                    self.tn.expect([b'config-if-epon', ], self.command_timeout)
                    return True
                else:
                    self.tn.write(b'n\n')
                    return False
            elif self.tn.expect([b'config-if-epon', ], self.command_timeout):
                print('modify success')
                return True
        except Exception as e:
            logger.error(e)
            return False

    def quit(self):
        try:
            self.tn.write(b'quit\n')
            time.sleep(self.command_interval)
            return True
        except Exception as e:
            print(e)
            return False

    def save_config(self):
        try:
            print('save')
            self.tn.write(b'save\n')
            self.tn.expect([b'<cr>', ], self.command_timeout)
            self.tn.write(b'\n\n')
            return True
        except Exception as e:
            print(e)
            return False

    def telnet_close(self):
        self.tn.close()


if __name__ == '__main__':

    def sync_cevlan(ip, username, password):

        # telnet olt
        tlt = TelnetDevice('', ip, username, password)
        return tlt.check_temperature()


    a = sync_cevlan(ip='172.30.4.12', username='monitor', password='shf-k61-906')
    for x in a:
        print(x)
