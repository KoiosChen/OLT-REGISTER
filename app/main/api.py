from flask import request, jsonify
from . import main
from ..MyModule.GetWorkorderInfo import *
from .. import redis_db, logger
import json


@main.route('/get_customer_info', methods=['POST'])
def get_customer_info():
    """
    用于获取工单平台用户数据数据
    :return:
    """
    if not redis_db.get('PERMIT_LIST'):
        redis_db.set('PERMIT_LIST', json.dumps({'permit': [], 'not permit': []}))
    permit_ip = json.loads(redis_db.get('PERMIT_LIST').decode())['permit']
    if 'all' in permit_ip or request.headers.get('X-Forwarded-For', request.remote_addr) in permit_ip:
        try:
            account_id = request.json['account_id']
            loginName = request.json['loginName']

            content = customerInfoQueryAction(account_id, loginName)

            if len(content['customerListInfo']['customerList']) > 0:
                content['customerListInfo']['customerList'][0]['password'] = ''

                return jsonify({'status': 'OK', 'content': content})
            else:
                return jsonify({'status': 'Fail', 'content': 'no customer found'})
        except Exception as e:
            logger.error(e)
            return jsonify({'status': 'Fail', 'content': 'PARAMETER ERROR'})
    else:
        return jsonify({'status': 'Fail',
                        'content': request.headers.get('X-Forwarded-For', request.remote_addr) + ' IS NOT PERMITTED'})
