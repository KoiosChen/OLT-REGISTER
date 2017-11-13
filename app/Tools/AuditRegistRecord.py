from ..models import OntRegister
from ..MyModule import GetWorkorderInfo
from .. import db
from time import sleep


def audit_regist_record():
    ontinfo = OntRegister.query.filter_by(reporter_name='技术部', regist_operator='技术部').all()
    for ont in ontinfo:
        if not ont.user_addr:
            x = GetWorkorderInfo.customerInfoQueryAction(ont.username, 'chenjzh')
            if x['customerListInfo']['customerList']:
                print(x['customerListInfo']['customerList'][0]['communityName'] + '/' + x['customerListInfo']['customerList'][0]['aptNo'])
                ont.user_addr = x['customerListInfo']['customerList'][0]['communityName'] + '/' + x['customerListInfo']['customerList'][0]['aptNo']
                db.session.add(ont)
                db.session.commit()
            sleep(0.1)