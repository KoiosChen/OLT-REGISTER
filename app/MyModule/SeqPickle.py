from ..models import CONFIG_FILE_PATH, aes_key
import os
import pickle
import time
import rsa
from .. import logger
from .SchedulerControl import scheduler_pause, scheduler_resume
from .AESCryptor import encrypt, decrypt
import binascii
import json


class Seq:
    def __init__(self, pkl_name):
        self.file = CONFIG_FILE_PATH + pkl_name
        if os.path.exists(self.file):
            seq_pkl = open(self.file, 'rb')
            if len(seq_pkl.read()) > 0:
                seq_pkl.seek(0)
                self.last_seq = pickle.load(seq_pkl)
                seq_pkl.close()
                self.init = False
            else:
                self.init = True
                self.last_seq = 0
                seq_pkl.close()
        else:
            self.init = True
            self.last_seq = 0

    def update_seq(self, seq):
        seq_pkl = open(self.file, 'wb')
        pickle.dump(seq, seq_pkl)
        seq_pkl.close()

    @property
    def load_seq(self):
        if os.path.exists(self.file):
            seq_pkl = open(self.file, 'rb')
            if len(seq_pkl.read()) > 0:
                seq_pkl.seek(0)
                seq_load = pickle.load(seq_pkl)
                seq_pkl.close()
                self.init = False
                return seq_load
            else:
                seq_pkl.close()
                return 0
        else:
            self.init = True
            return 0

    def init_today_seq(self):
        pass


def checkLicence(init='0'):
    """

    :param init:
    :return:
    """
    check_interval = 30
    check_licence = Seq('licence.pkl')
    if check_licence.init:
        init_json = init_licence(init)
        check_licence.update_seq(init_json)
        if init == '0':
            scheduler_pause()
        return init_json
    else:
        lp = check_licence.load_seq

        print('load licecne.pkl', lp, type(lp))
        print(lp['expire_in'], lp['expire_date'], lp['start_date'], lp['status'])

        if lp['expire_in'] == 0 or lp['expire_date'] <= lp['start_date'] or lp['status'] == '0':
            logger.critical('The licence has been expired, '
                            'pls ask Koios to buy new licence if your still want to use R2D2.')
            lp['status'] = '0'
            lp['expire_in'] = 0
            scheduler_pause()
        else:
            lp['expire_in'] -= check_interval

        check_licence.update_seq(lp)
        return lp


def init_licence(status):
    # 产生私钥
    init_days = 7
    (pubkey, privkey) = rsa.newkeys(2048)
    print(pubkey, privkey)
    pubkey = encrypt(pubkey.save_pkcs1().decode(), aes_key)
    privkey = encrypt(privkey.save_pkcs1().decode(), aes_key)

    init_data = {"init_date": time.time(),
                 "start_date": time.time(),
                 "expire_in": init_days * 86400 if status != '0' else 0,
                 "expire_date": time.time() + init_days * 86400,
                 "pubkey": pubkey,
                 "privkey": privkey,
                 "rules": "",
                 "author": "Koios",
                 "status": status}
    print('init data', init_data)

    return init_data


def update_crypted_licence(crypt_licence):
    new_licence = binascii.a2b_hex(crypt_licence.encode())
    privkey = get_loaded_privkey()
    newone = rsa.decrypt(new_licence, privkey).decode()
    dic_new = json.loads(newone)

    lic_pkl = Seq('licence.pkl')
    if lic_pkl.init:
        lic_pkl.update_seq(init_licence('0'))
        return False
    else:
        licence = lic_pkl.load_seq
        for k, v in dic_new.items():
            print(k, v)
        dic_new['privkey'] = licence['privkey']
        dic_new['pubkey'] = licence['pubkey']
        lic_pkl.update_seq(dic_new)

        # 如果许可证状态不可用,说明这时需要resume scheduler
        if licence['expire_in'] <= 0 or licence['expire_date'] <= licence['start_date'] or licence['status'] == '0':
            scheduler_resume()
        return True


def get_pubkey():
    lic_pkl = Seq('licence.pkl')
    if lic_pkl.init:
        return False
    else:
        licence = lic_pkl.load_seq
        decrypted_licence = decrypt(licence['pubkey'], aes_key)
        return (licence['expire_date'],
                licence['expire_in'],
                decrypted_licence.decode())


def get_loaded_privkey():
    lic_pkl = Seq('licence.pkl')
    if lic_pkl.init:
        logger.critical('Licence is not exist!')
        return False
    else:
        licence = lic_pkl.load_seq
        return rsa.PrivateKey.load_pkcs1(decrypt(licence['privkey'].decode(), aes_key))


def gen_rsa():
    lic_pkl = Seq('licence.pkl')
    if lic_pkl.init:
        lic_pkl.update_seq(init_licence('0'))
        return False
    else:
        (pubkey, privkey) = rsa.newkeys(1024)
        licence = lic_pkl.load_seq
        licence['pubkey'] = pubkey.save_pkcs1().decode()
        licence['privkey'] = privkey.save_pkcs1().decode()
        lic_pkl.update_seq(licence)
        return True
