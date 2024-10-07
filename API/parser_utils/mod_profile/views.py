import json

import parser_utils.config
from parser_utils import make_response, printLog, logger, connect_to_db, clear_log
from parser_utils.mod_util.utils import logout_user, logout_group
from .utils import delete_user, add_group, add_user, delete_group, \
    check_user_existance, check_group_existance, get_user_list, get_group_list, \
    get_quota_limitation, get_user_mac_auth_data, change_username, change_groupname, \
    change_user_password


# mod_profile = Blueprint('mod_profile', __name__, url_prefix='/profile')


###############################################################################

# @mod_profile.route('/user/add', methods=['POST'])
def profile_user_add(content):
    # content = request.get_json()
    printLog(content)
    # if parser.config['PROFILE_USERNAME_U'] not in list(content.keys()):
    #     abort(400)

    add_user_result = add_user(content)

    if add_user_result == 1:
        return "OK"
    elif add_user_result == 0:
        return make_response(400, 'Data type or structure is wrong')
    elif add_user_result == -1:
        return make_response(500, "Error in saving profile in database.")
    elif add_user_result == -2:
        return make_response(400, 'One of recived MACs is already exists in database.')
    else:
        return make_response(500, 'Unknown Error')


###############################################################################

# @mod_profile.route('/user/delete', methods=['POST'])
def profile_user_delete(content):
    # content = request.get_json()
    printLog(content)
    # if parser.config['PROFILE_USERNAME_U'] not in list(content.keys()):
    #     abort(400)

    logout_user(content[parser_utils.config['PROFILE_USERNAME_U']])
    delete_result = delete_user(content[parser_utils.config['PROFILE_USERNAME_U']])
    clear_log('user', key=content[parser_utils.config['PROFILE_USERNAME_U']])

    if not delete_result:
        return make_response(500, 'Error in delete operation, User: %s' \
                             % content[parser_utils.config['PROFILE_USERNAME_U']])
    elif delete_result == 'Not Found' or delete_result == 'Deleted':
        return make_response(200, 'OK')
    else:
        return make_response(500, 'Unknown Error')


###############################################################################

# @mod_profile.route('/user/update', methods=['POST'])
def profile_user_update(content):
    # content = request.get_json()
    printLog(content)
    # if parser.config['PROFILE_USERNAME_U'] not in list(content.keys()) or \
    #                 parser.config['PROFILE_FORCE_LOGOUT_U'] not in list(content.keys()):
    #     abort(400)

    old_MACs = get_user_mac_auth_data(content[parser_utils.config['PROFILE_USERNAME_U']])

    con = next(connect_to_db())
    if not con:
        return make_response(500, 'Error in create connection.')

    delete_result = delete_user(content[parser_utils.config['PROFILE_USERNAME_U']],
                                ps_con=con, commit=False)

    if not delete_result:
        return make_response(500, 'Error in update operation, User: %s' \
                             % content[parser_utils.config['PROFILE_USERNAME_U']])
        # elif delete_result == 'Not Found':
        # return make_response(500, "I haven't username=%s" % \
        # content[parser.config['PROFILE_USERNAME_U']])
    elif delete_result == 'Deleted' or delete_result == 'Not Found':

        try:
            old_MACs_extra = [x for x in old_MACs if x not in content[parser_utils.config['PROFILE_MAC_AUTH_U']]]
            new_MACs_extra = [x for x in content[parser_utils.config['PROFILE_MAC_AUTH_U']] if x not in old_MACs]
        except KeyError:
            old_MACs_extra = None
            new_MACs_extra = None

        if content[parser_utils.config['PROFILE_FORCE_LOGOUT_U']] or \
                old_MACs_extra or new_MACs_extra:
            logout_user(content[parser_utils.config['PROFILE_USERNAME_U']])

        clear_log('user', key=content[parser_utils.config['PROFILE_USERNAME_U']],
                  details_type='existance')

        add_user_result = add_user(content, ps_con=con)

        if add_user_result == 1:
            return make_response(200, "OK")
        elif add_user_result == 0:
            return make_response(400, 'Data type or structure is wrong')
        elif add_user_result == -1:
            return make_response(500, "Error in updating profile in database.")
        elif add_user_result == -2:
            return make_response(400, 'One of recived MACs is already exists in database.')
        else:
            return make_response(500, 'Unknown Error')

    else:
        return make_response(500, 'Unknown Error')


###############################################################################

# @mod_profile.route('/group/add', methods=['POST'])
def profile_group_add(content):
    # content = request.get_json()
    printLog(content)

    # if parser.config['PROFILE_GROUPNAME_G'] not in list(content.keys()) or \
    #                 parser.config['PROFILE_ATTRIBUTES_G'] not in list(content.keys()) or \
    #         not content[parser.config['PROFILE_ATTRIBUTES_G']]:
    #     abort(400)

    add_group_result = add_group(content)

    if not add_group_result:
        return make_response(500, 'Error in saving Group: %s' \
                             % content[parser_utils.config['PROFILE_GROUPNAME_G']])

    return "OK"


###############################################################################

# @mod_profile.route('/group/delete', methods=['POST'])
def profile_groups_delete(content):
    # content = request.get_json()
    printLog(content)

    # if parser.config['PROFILE_GROUPNAME_G'] not in list(content.keys()):
    #     abort(400)

    delete_group_result = delete_group(content[parser_utils.config['PROFILE_GROUPNAME_G']])
    if delete_group_result == -1:
        return make_response(500, 'Error in delete operation, Group: %s' \
                             % content[parser_utils.config['PROFILE_GROUPNAME_G']])
    elif delete_group_result == 1 or delete_group_result == 0:
        clear_log('group', key=content[parser_utils.config['PROFILE_GROUPNAME_G']])
        logout_group(content[parser_utils.config['PROFILE_GROUPNAME_G']])
        return make_response(200, "OK")
    else:
        return make_response(500, 'Unknown Error')


###############################################################################

# @mod_profile.route('/group/update', methods=['POST'])
def profile_group_update(content):
    # content = request.get_json()
    printLog(content)
    #
    # if parser.config['PROFILE_GROUPNAME_G'] not in list(content.keys()) or \
    #                 parser.config['PROFILE_FORCE_LOGOUT_G'] not in list(content.keys()) or \
    #                 parser.config['PROFILE_ATTRIBUTES_G'] not in list(content.keys()) or \
    #         not content[parser.config['PROFILE_ATTRIBUTES_G']]:
    #     abort(400)

    con = next(connect_to_db())
    if not con:
        return make_response(500, 'Error in create connection.')

    delete_group_result = delete_group(content[parser_utils.config['PROFILE_GROUPNAME_G']], \
                                       ps_con=con, commit=False, delete_users=False)

    if delete_group_result == -1:
        return make_response(500, 'Error in update operation, Group: %s' \
                             % content[parser_utils.config['PROFILE_GROUPNAME_G']])
    elif delete_group_result in (0, 1):
        clear_log('group', key=content[parser_utils.config['PROFILE_GROUPNAME_G']])
        add_group_result = add_group(content, ps_con=con)

        if not add_group_result:
            return make_response(500, 'Error in updating Group: %s' \
                                 % content[parser_utils.config['PROFILE_GROUPNAME_G']])
        else:
            if content[parser_utils.config['PROFILE_FORCE_LOGOUT_G']]:
                logout_group(content[parser_utils.config['PROFILE_GROUPNAME_G']])
            return 'OK'
    else:
        return make_response(500, 'Unknown Error')


###############################################################################

# @mod_profile.route('/check_users', methods=['POST'])
def check_user_existance_view(content):
    # content = request.get_json()
    printLog(content)
    if isinstance(content, list):
        return make_response(400, 'You must send me a list!')

    users_status = {}

    for username in content:
        result = check_user_existance(username)
        if not result:
            users_status[username] = 0
        else:
            users_status[username] = 1

    return json.dumps(users_status)


###############################################################################

# @mod_profile.route('/check_groups', methods=['POST'])
def check_group_existance_view(content):
    # content = request.get_json()
    printLog(content)

    if isinstance(content, list):
        return make_response(400, 'You must send me a list!')

    groups_status = {}

    for groupname in content:
        result = check_group_existance(groupname)
        if not result:
            groups_status[groupname] = 0
        else:
            groups_status[groupname] = 1

    return json.dumps(groups_status)


###############################################################################

# @mod_profile.route('/quota_limit/<username>')
def get_quota_limitation_view(username):
    return json.dumps(get_quota_limitation(username))


###############################################################################

# @mod_profile.route('/user_list')
def user_list_view():
    users = list(get_user_list())
    printLog(users)
    return make_response(json.dumps(users), mimetype='application/json')


###############################################################################

# @mod_profile.route('/group_list')
def group_list_view():
    groups = list(get_group_list())
    printLog(groups)
    return make_response(json.dumps(groups), mimetype='application/json')


###############################################################################

# @mod_profile.route('/user/change_password', methods=['POST'])
def change_password_view(content):
    # content = request.get_json()
    printLog(content)
    response = None

    try:
        if check_user_existance(content['user']):
            result = change_user_password(content['user'],
                                          content['new_password'],
                                          content['old_password'])
            if result == 1:
                response = make_response(200, 'OK')
            elif result == 2:
                response = make_response(500, "Old password is wrong.")
            else:
                response = make_response(500, "Can't save in database.")

        else:
            response = make_response(400, 'User = %s is not exists' % \
                                     content['user'])
    except KeyError as e:
        logger.error(str(e))
        response = make_response(400, 'KeyError: %s' % str(e))

    return response


###############################################################################

# @mod_profile.route('/change_username', methods=['POST'])
def change_username_view(content):
    # content = request.get_json()
    printLog(content)
    response = None

    try:
        if check_user_existance(content['old']):
            if change_username(content['old'],
                               content['new']):
                logout_user(content['old'])
                response = make_response(200, 'OK')
            else:
                response = make_response(500, "Can't save in database.")

        else:
            response = make_response(404, 'Group = %s is not exists' % \
                                     content['old'])
    except KeyError as e:
        logger.error(str(e))
        response = make_response(400, 'KeyError: %s' % str(e))

    return response


###############################################################################

# @mod_profile.route('/change_groupname', methods=['POST'])
def change_groupname_view(content):
    # content = request.get_json()
    printLog(content)
    response = None

    try:
        if check_group_existance(content['old']):
            if change_groupname(content['old'],
                                content['new']):
                logout_group(content['old'])
                response = make_response(200, 'OK')
            else:
                response = make_response(500, "Can't save in database.")
        else:
            response = make_response(404, 'Group = %s is not exists' % \
                                     content['old'])
    except KeyError as e:
        logger.error(str(e))
        response = make_response(400, 'KeyError: %s' % str(e))

    return response

###############################################################################
