import datetime
import json

from parser_utils import make_response, clear_log
from .utils import *


# mod_qos = Blueprint('mod_qos', __name__, url_prefix='/QoS')


################################################################################

# @mod_qos.route('/policy/add', methods=['POST'])
def add_policy_view(content):
    # content = request.get_json()
    printLog(content)

    try:
        result = add_policy(content)
    except KeyError as e:
        logger.error(str(e))
        return make_response(400, str(e))

    if result == 2 or result == 6:
        return make_response(200, 'OK')
    elif result == 4:
        return make_response(200, "Added with some problems")
    elif result == 1:
        return make_response(500, 'Error in middleware')
    elif result == False:
        return make_response(500, 'Can not save in database.')


################################################################################

# @mod_qos.route('/policy/delete', methods=['POST'])
def delete_policy_view(content):
    # content = request.get_json()
    printLog(content)

    try:
        if not test_policy_exstance(content['policy_id']):
            return make_response(200, 'There is not policy with id = %s' % \
                                 content['policy_id'])
        clear_log('qos_policy', key=content['policy_id'])
        result = delete_policy(content['policy_id'])
    except KeyError as e:
        return make_response(400, str(e))

    if result == 2 or result == 6:
        return make_response(200, 'OK')
    elif result == 4:
        return make_response(200, "Added with some problems")
    elif result == 1:
        return make_response(500, 'Error in middleware')
    elif result == None:
        return make_response(500, 'Can not save in database.')


################################################################################

# @mod_qos.route('/policy/update', methods=['POST'])
def update_policy_view(content):
    # content = request.get_json()
    printLog(content)

    try:
        if test_policy_exstance(content['policy_id']):
            clear_log('qos_policy', key=content['policy_id'])
            result = update_policy(content)
        else:
            result = add_policy(content)
    except KeyError as e:
        return make_response(400, str(e))

    if result == 2 or result == 6:
        return make_response(200, 'OK')
    elif result == 4:
        return make_response(200, "Added with some problems")
    elif result == 1:
        return make_response(500, 'Error in middleware')
    elif result == False:
        return make_response(500, 'Can not save in database.')


################################################################################

# @mod_qos.route('/policy/change_order', methods=['POST'])
def change_policy_order_view(content):
    # content = request.get_json()
    printLog(content)

    try:

        if test_policy_exstance(content['policy_id']):
            result = change_policy_order(content['policy_id'],
                                         content['order'])
        else:
            return make_response(404, 'There is not policy with ID = %s' % \
                                 content['policy_id'])

    except KeyError as e:
        logger.error(str(e))
        return make_response(400, str(e))

    if result == True:
        return make_response(200, 'OK')
    else:
        return make_response(500, 'Can not save in database.')


################################################################################

# @mod_qos.route('/policy/change_status', methods=['POST'])
def change_policy_status_view(content):
    # content = request.get_json()
    printLog(content)

    try:
        if test_policy_exstance(content['policy_id']):
            clear_log('qos_policy', key=content['policy_id'])
            result = change_policy_status(content['policy_id'],
                                          content['enable'])
        else:
            return make_response(404, 'There is not policy with ID = %s' % \
                                 content['policy_id'])

    except KeyError as e:
        logger.error(str(e))
        return make_response(400, str(e))

    if result == 2 or result == 6 or result == True:
        return make_response(200, 'OK')
    elif result == 4:
        return make_response(200, "Enabled with some problems")
    elif result == 1:
        return make_response(500, 'Error in middleware')
    elif result == False:
        return make_response(500, 'Can not save in database.')


################################################################################
# @mod_qos.route('/shaper/add', methods=['POST'])
def add_shaper_view(content):
    # content = request.get_json()
    printLog(content)

    try:
        if test_shaper_exstance(content['shaper_id']):
            result = update_shaper(content)
        else:
            result = add_shaper(content)
    except KeyError as e:
        return make_response(400, str(e))

    if result == True:
        return make_response(200, 'OK')
    else:
        return make_response(500, 'Can not save in database.')


################################################################################

# @mod_qos.route('/shaper/delete', methods=['POST'])
def delete_shaper_view(content):
    # content = request.get_json()
    printLog(content)
    response = None

    try:
        result = delete_shaper(content['shaper_id'])
    except KeyError as e:
        return make_response(400, str(e))

    if result == 2 or result == 6:
        response = make_response(200, 'OK')
    elif result == 4:
        response = make_response(200, "Enabled with some problems")
    elif result == 1:
        response = make_response(500, 'Error in middleware')
    elif result == False:
        response = make_response(500, 'Can not save in database.')

    return response


################################################################################

# @mod_qos.route('/shaper/update', methods=['POST'])
def update_shaper_view(content):
    # content = request.get_json()
    printLog(content)
    response = None

    try:
        if test_shaper_exstance(content['shaper_id']):
            result = update_shaper(content)
        else:
            result = add_shaper(content)
    except KeyError as e:
        return make_response(400, str(e))

    if result == 2 or result == 6 or result == True:
        response = make_response(200, 'OK')
    elif result == 4:
        response = make_response(200, "Enabled with some problems")
    elif result == 1:
        response = make_response(500, 'Error in middleware')
    elif result == False:
        response = make_response(500, 'Can not save in database.')

    return response


################################################################################

# @mod_qos.route('/general_config', methods=['POST'])
def set_general_config_view(content):
    # content = request.get_json()
    printLog(content)
    response = None

    try:
        result = set_general_config(content)
    except KeyError as e:
        return make_response(400, str(e))

    if result == 2 or result == 6:
        response = make_response(200, 'OK')
    elif result == 4:
        response = make_response(200, "Added with some problems")
    elif result == 1:
        response = make_response(500, 'Error in middleware')
    elif result == False:
        response = make_response(500, 'Can not save in database.')

    return response


################################################################################

# @mod_qos.route('/general_config/change_status', methods=['POST'])
def delete_general_config_view(content):
    # content = request.get_json()
    printLog(content)
    response = None

    if all([x in list(content.keys()) for x in ('interface', 'enable')]):
        result = change_status_interface(content['interface'],
                                         content['enable'])

        if result == 2 or result == 6 and result == True:
            response = make_response(200, 'OK')
        elif result == 4:
            response = make_response(200, "Added with some problems")
        elif result == 1:
            response = make_response(500, 'Error in middleware')
        elif result == None:
            response = make_response(500, 'Can not save in database. our not found.')
    else:
        response = make_response(400,
                                 "Check 'enable' and 'interface' fields (existance)")

    return response


################################################################################

# @mod_qos.route('/policy_list')
def get_policy_list_view():
    return make_response(json.dumps(get_policy_list()), mimetype='application/json')


################################################################################

# @mod_qos.route('/policy/update_by_id', methods=['POST'])
def update_by_id_view(content):
    # content = request.get_json()
    printLog(content)

    try:
        if test_policy_exstance(content['policy_id']):
            clear_log('qos_policy', key=content['policy_id'])
            result = update_policy_by_id(content['policy_id'])
        else:
            result = add_policy(content)
    except KeyError as e:
        return make_response(400, str(e))

    if result == 2 or result == 6:
        return make_response(200, 'OK')
    elif result == 4:
        return make_response(200, "Added with some problems")
    elif result == 1:
        return make_response(500, 'Error in middleware')
    elif result == False:
        return make_response(500, 'Can not save in database.')


################################################################################

# @mod_qos.route('/interface_chart')
def interface_chart_view(request):
    traffic_type = request.args.get('traffic_type', None)
    interface = request.args.get('interface', None)

    if traffic_type not in ('download', 'upload'):
        return make_response(400, 'send "download" or "upload" for traffic_type')
    if not interface:
        return make_response(400, 'send interface name in query string.')

    data = get_interface_shaper_chart(interface, traffic_type)
    if data == -1:
        response = make_response(400, "interface name is wrong or it's disable")
    elif data == None:
        response = make_response(500, "internal server error.")
    elif data:
        response = json.dumps({'data': data})
    return response


################################################################################

# @mod_qos.route('/class_chart')
def class_chart_view(request):
    policy_id = request.args.get('policy_id', None)
    ui_shaper_id = request.args.get('shaper_id', None)
    interface = request.args.get('interface', None)
    traffic_type = request.args.get('traffic_type', None)
    date_from = request.args.get('date_from', None)

    if not (interface or traffic_type):
        return make_response(400,
                             'send "interface" and "traffic_type" in query string')
    if not (policy_id or ui_shaper_id):
        return make_response(400, 'send "policy_id" or "shaper_id" in query string')

    if date_from:
        try:
            date_from = datetime.datetime.strptime(date_from, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return make_response(400,
                                 '"date_from" format is not match with "%Y-%m-%d %H:%M:%S"')
    else:
        date_from = datetime.datetime.now() - datetime.timedelta(days=1)

    if policy_id:
        result = get_shaper_id_of_policy_interface(interface, int(policy_id), traffic_type)
    else:
        shaper_id = convert_ui_shaper_id_to_low_level_id(ui_shaper_id)
        if shaper_id:
            result = {'shaper_id': int(shaper_id), 'parent_id': 1}
        elif shaper_id == None:
            return make_response(400, 'shaper_id: %s is not exists' % ui_shaper_id)

    if result:
        data = get_tc_data(interface, result['shaper_id'], result['parent_id'],
                           date_from, traffic_type)
    elif result is False:
        return make_response(400, "There is no policy with id: %s on interface %s" % \
                             (policy_id, interface))
    else:
        data = list()

    if data or data == []:
        return json.dumps({'data': data})
    else:
        return make_response(500, "internal server error!")
