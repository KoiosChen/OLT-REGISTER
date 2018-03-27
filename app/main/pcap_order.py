from . import main
from ..MyModule.GetWorkorderInfo import *
from .. import redis_db, logger
import json
import uuid
from flask import redirect, session, url_for, render_template, flash, request, jsonify
from .forms import PcapOrder


def submit_order(accountId, question):
    id = uuid.uuid1()
    send_content = {"id": str(id),
                    "accountId": accountId,
                    "login_name": session['LOGINUSER'],
                    "username": session['LOGINNAME'],
                    "question": question}
    headers = {'Content-Type': 'application/json', "encoding": "utf-8"}
    send_sms_url = 'http://127.0.0.1:54321/submit_pcap_order'
    r = requests.post(send_sms_url, data=json.dumps(send_content, ensure_ascii=False).encode('utf-8'), headers=headers)
    result = r.json()
    print(result)

    if result['status'] == 'ok':
        return True
    else:
        return False


@main.route('/pcap_order', methods=['GET', 'POST'])
def pcap_order():
    form = PcapOrder()
    if form.validate_on_submit():
        submit_order(form.accountId.data, form.question.data)
    return render_template('pcap_order.html', form=form)