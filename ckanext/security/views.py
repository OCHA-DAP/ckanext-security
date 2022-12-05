# -*- coding: utf-8 -*-

import logging
import json

from ckanext.security.model import SecurityTOTP

from ckan.views import user
from ckanext.security import utils, authenticator
from ckan.lib import helpers
from flask import Blueprint, make_response, request
from functools import wraps
from ckan.plugins import toolkit as tk
from ckan.model import User
from ckanext.security.cache.login import LoginThrottle

log = logging.getLogger(__name__)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        utils.check_user_and_access()
        return f(*args, **kwargs)
    return decorated_function


mfa_user = Blueprint("mfa_user", __name__)


def login():
    headers = {'Content-Type': 'application/json'}
    (status, res_data) = utils.login()
    return make_response((res_data, status, headers))

def check_lockout():
    user_name = request.args['user']
    locked = False
    lockout = {}
    throttle = LoginThrottle(User.by_name(user_name), user_name)
    if throttle:
        locked = throttle.is_locked()
        if locked:
            lockout['timeout'] = throttle.login_lock_timeout

    lockout['result'] = locked
    return json.dumps(lockout)

def check_mfa():
    user_name = request.args['user']
    totp_challenger = SecurityTOTP.get_for_user(user_name)
    return json.dumps({'result': totp_challenger is not None})

@login_required
def configure_mfa(id=None):
    extra_vars = utils.configure_mfa(id)
    return tk.render('security/configure_mfa.html',
                     extra_vars={'c': extra_vars})


@login_required
def new(id=None):
    utils.new(id)
    return helpers.redirect_to('mfa_user.configure_mfa', id=id)

@login_required
def delete(id=None):
    totp_challenger = SecurityTOTP.get_for_user(id)
    if totp_challenger:
        totp_challenger.delete()
        totp_challenger.commit()
    return helpers.redirect_to('mfa_user.configure_mfa', id=id)


mfa_user.add_url_rule('/api/mfa_login', view_func=login, methods=['POST'])
mfa_user.add_url_rule('/configure_mfa/<id>',
                      view_func=configure_mfa, methods=['GET', 'POST'])
mfa_user.add_url_rule('/configure_mfa/<id>/new',
                      view_func=new, methods=['GET', 'POST'])
mfa_user.add_url_rule('/configure_mfa/<id>/delete',
                      view_func=delete, methods=['GET'])
mfa_user.add_url_rule('/api/check_lockout', view_func=check_lockout, methods=['GET'])
mfa_user.add_url_rule('/api/check_mfa', view_func=check_mfa, methods=['GET'])


def get_blueprints():
    return [mfa_user]
