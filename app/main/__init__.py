from flask import Blueprint

main = Blueprint('main', __name__)

from . import views, errors, api, ont_regist, view_ont_register_from_accountid, pcap_order, register_robot