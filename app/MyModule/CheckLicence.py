from .SeqPickle import *
from .. import logger


def checkLicence(init='0'):
    """

    :param init:
    :return:
    """
    check_licence = Seq('licence.pkl')
    if check_licence.init:
        init_json = init_licence(init)
        check_licence.update_seq(init_json)
        return False
    else:
        lp = check_licence.load_seq

        print('load licecne.pkl', lp, type(lp))
        print(lp['expire_in'], lp['expire_date'], lp['start_date'], lp['status'])

        if lp['expire_in'] == 0 or lp['expire_date'] <= lp['start_date'] or lp['status'] == '0':
            logger.critical('The licence has been expired, '
                            'pls ask Koios to buy new licence if your still want to use R2D2.')
            lp['status'] = '0'
            lp['expire_in'] = 0
            return False
        else:
            return True
