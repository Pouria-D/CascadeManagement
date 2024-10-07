# from flask import Blueprint, jsonify, abort, request
import json

from parser_utils import make_response
from .utils import logout_user, logout_group, update, get_updating_status


# mod_util = Blueprint('mod_util', __name__)


################################################################################

# @mod_util.route('/users-logout', methods=['POST'])
def user_logout_view(content):
    # content = request.get_json()
    # if 'users' not in list(content.keys()):
    #     abort(400)

    for user in content['users']:
        logout_user(user)

    return make_response(200, "OK")


################################################################################

# @mod_util.route('/groups-logout', methods=['POST'])
def group_logout_view(content):
    # content = request.get_json()

    # if 'groups' not in list(content.keys()):
    #     abort(400)

    for group in content['groups']:
        logout_group(group)

    return make_response(200, "OK")


################################################################################

# @mod_util.route('/update')
def run_updater_view():
    result = update()
    if result[0]:
        return make_response(200, "OK")
    else:
        return make_response(200, result[1])


################################################################################

# @mod_util.route('/updating_status')
def updating_status_view():
    status = get_updating_status()
    if status:
        return json.dumps({'updating': True})
    else:
        return json.dumps({'updating': False})

################################################################################
