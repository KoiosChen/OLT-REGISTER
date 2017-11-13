from flask import render_template, redirect, request, url_for, flash, session
from flask_login import login_user, logout_user, login_required
from ..models import User, Area
from .forms import LoginForm
from . import auth
from .. import logger


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        logger.warning('Somebody is trying to login as {}'.format(form.email.data))
        user = User.query.filter_by(email=form.email.data, status=1).first()
        if user is not None and user.verify_password(form.password.data):
            # session.permanent = True
            logger.warning('Username is {}'.format(user.username))
            this_user = User.query.filter_by(email=form.email.data).first()
            this_user_area = Area.query.filter_by(id=this_user.area).first()
            if this_user.permit_machine_room == '0x0':
                session['permit_machine_room'] = this_user_area.area_machine_room
            else:
                session['permit_machine_room'] = this_user.permit_machine_room
            session['LOGINUSER'] = form.email.data
            session['LOGINNAME'] = this_user.username
            session['LOGINAREA'] = this_user.area
            session['ROLE'] = this_user.role_id
            session['DUTY'] = this_user.duty
            session['SELFID'] = this_user.id
            logger.debug('{} {}'.format(session['ROLE'], session['SELFID']))
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        logger.warning('This email is not existed')
        flash('用户名密码错误')
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    logger.warning('User {} logout'.format(session.get('LOGINNAME')))
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('.login'))
