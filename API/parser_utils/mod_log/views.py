import json

import requests

from parser_utils import make_response
from .utils import *


################################################################################


# @mod_log.route('/user_login_history')
def get_user_login_history_view(request):
    username = request.args.get('username', None)
    if not username:
        response = make_response(400, 'Enter username as query string.')
    else:
        data = get_user_login_history(username)
        response = make_response(json.dumps(data), mimetype='application/json')
    return response


################################################################################

# @mod_log.route('/version')
def version_viwe():
    response = None

    try:
        current_version_resp = requests.get(parser_utils.config['UPDATE_MANAGER'] + 'current_version')
        current_version = current_version_resp.json()['current_version']

        new_update_resp = requests.get(parser_utils.config['UPDATE_MANAGER'] + 'new_update')
        if not new_update_resp.json():
            data = {'update': False, 'current_version': str(current_version)}
        else:
            keys = ('version', 'description', 'state')
            if all([i in new_update_resp.json() for i in keys]):
                data = {
                    'update': True,
                    'latest_version_in_server': new_update_resp.json()['version'],
                    'description': new_update_resp.json()['description'],
                    'state': new_update_resp.json()['state'],
                    'current_version': str(current_version),
                    'error_message': None
                }
            elif 'error_message' in new_update_resp.json():
                data = {
                    'update': False,
                    'latest_version_in_server': None,
                    'description': None,
                    'current_version': str(current_version),
                    'error_message': new_update_resp.json()['error_message']
                }

        response = json.dumps(data)
    except Exception as e:
        logger.info(str(e))
        data = {
            'update': False,
            'latest_version_in_server': None,
            'description': None,
            'current_version': 'UNKNOWN',
            'error_message': 'Can not connect to update manager..'
        }
        response = json.dumps(data)

    return response
