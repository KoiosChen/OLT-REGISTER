from flask import redirect, session, url_for, render_template, flash, request, jsonify
from flask_login import login_required
from ..models import *
from ..decorators import admin_required, permission_required
from ..my_func import *
from .forms import *
from . import main
import time
import json
from ..MyModule.GetWorkorderInfo import customerInfoQueryAction
from ..MyModule.OntStatus import ontLocation
from .. import db, logger


@main.route('/register_record_report', methods=['GET'])
@login_required
@permission_required(Permission.COMMENT)
def register_record_report():
    if session.get('REGIST_RESULT') is not None:
        flash(session['REGIST_RESULT'])
        session['REGIST_RESULT'] = None
    session['index'] = 'from_index_file'
    return render_template('index.html')
