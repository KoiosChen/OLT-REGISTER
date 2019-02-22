from flask import request, jsonify
from . import main
from ..MyModule.GetWorkorderInfo import *
from .. import redis_db, logger
from ..decorators import permission_ip
import json


@main.route('/get_customer_info', methods=['POST'])
@permission_ip
def get_customer_info():
    """
    用于获取工单平台用户数据数据
    :return:
    """
    try:
        account_id = request.json['account_id']
        loginName = request.json['loginName']
        hidden_param = request.json.get('_hidden_param')

        content = customerInfoQueryAction(account_id, loginName)
        print(content)

        if len(content['customerListInfo']['customerList']) > 0:
            if not hidden_param:
                content['customerListInfo']['customerList'][0]['password'] = ''

            return jsonify({'status': 'OK', 'content': content})
        else:
            return jsonify({'status': 'Fail', 'content': 'no customer found'})
    except Exception as e:
        logger.error(e)
        return jsonify({'status': 'Fail', 'content': 'PARAMETER ERROR'})


@main.route('/batch_register', methods=['POST'])
@permission_ip
def batch_register():
    data = request.json
