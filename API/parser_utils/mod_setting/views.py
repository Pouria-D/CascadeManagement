import parser_utils.config
from parser_utils import make_response
from parser_utils.mod_setting import update_default_routes
from .utils import *


################################################################################
# @mod_setting.route('/sharedkey', methods=['POST'])
def change_sharedkey(content):
    try:
        if 'just_check' in list(content.keys()) and \
                        content['just_check'] == True:
            if set_shared_key(content['shared_key'], just_check_key=True):
                return "OK"
            else:
                return make_response(500, "Is not sync.")
        else:
            if not set_shared_key(content['shared_key']):
                make_response(500, "Can not set shared key.")

    except KeyError:
        return make_response(400, "KeyError occourd.")

    return "OK"


################################################################################

# @mod_setting.route('/multiwan/set', methods=['POST'])
def multiwan_add_view(content):
    # if request.get_json() == None:
    #     abort(400)

    # printLog(request.get_json())
    # content = request.get_json()

    try:
        if check_first_multiwan_opration():
            if add_default_route_table() == 50 or 30:
                if add_default_rule() != 50 and 30:
                    return make_response(500, 'Error in add default rule.')
            else:
                return make_response(500, 'Error in add default route table.')

        db_save_result = save_multiwan_record_db(content['interface'],
                                                 content['weight'], content['enable'])

        if db_save_result:
            mwlink_data = get_mwlink_data()
            result = update_default_routes(mwlink_data)
            if result == 50:
                return make_response(200, 'OK')
            else:
                return make_response(500, 'Error in mwlink.')
        else:
            return make_response(500, 'Error in save multiwan data in database.')

    except KeyError as e:
        logger.error(str(e))
        return make_response(400, 'KeyError')

    return make_response(200, 'OK')


################################################################################

# @mod_setting.route('/multiwan/set_all')
def multiwan_add_all_view():
    mwlink_data = get_mwlink_data()
    if mwlink_data:
        result = update_default_routes(mwlink_data)
        if result == 50:
            return make_response(200, 'OK')
        else:
            return make_response(500, 'Error in mwlink.')
    else:
        return make_response(200, 'OK')


################################################################################

# @mod_setting.route('/multiwan/check_interface_status/<interface>')
# def multiwan_check_interface_status_view(interface):
#     result = check_mwlink_interface_is_enable(interface)
#     if result:
#         return 'true'
#     else:
#         return 'false'


################################################################################

# @mod_setting.route('/multiwan/add_defaults')
def multiwan_add_defaults_view():
    if add_multiwan_defaults():
        return make_response(200, 'OK')
    else:
        return make_response(500, 'Error in mwlink.')


################################################################################
# @mod_setting.route('/multiwan/delete', methods=['POST'])
def multiwan_delete_view(content):
    # if request.get_json() == None:
    #     abort(400)

    # printLog(request.get_json())
    # content = request.get_json()

    try:
        db_delete_result = delete_multiwan_record_db(content['interface'])
        if db_delete_result:
            mwlink_data = get_mwlink_data()
            if mwlink_data:
                result = update_default_routes(mwlink_data)
            else:
                result = 50
            if result == 50:
                return make_response(200, 'OK')
            else:
                return make_response(500, 'Error in mwlink.')
        else:
            return make_response(500, 'Error in save multiwan data in database.')
    except KeyError as e:
        logger.error(str(e))
        return make_response(400, 'KeyError')

    return make_response(200, 'OK')


################################################################################

# @mod_setting.route('/multiwan/check', methods=['POST'])
def multiwan_check_view(content):
    # if request.get_json() == None:  abort(400)
    # printLog(request.get_json())
    # content = request.get_json()
    response = dict()
    ppp_map = get_pppoe_interfaces_map()
    for interface in content:
        if interface in ppp_map:
            interface = ppp_map[interface]
        gw = get_interface_gateway(interface)
        status = check_gateway(gw)
        status = True if status == 80 else False
        response[interface] = {
            'gateway': gw,
            'status': status
        }
    return make_response(json.dumps(response), mimetype='application/json')


################################################################################

# @mod_setting.route('/captive_portal_setting', methods=['GET', 'POST'])
def set_chilli_configs_view(data, method):
    ppp_map = get_pppoe_interfaces_map()

    if method == 'POST':
        content = data

        wan = str()
        for interface in content[parser_utils.config['CHILLI_WAN']]:
            if interface in ppp_map:
                wan += ",%s" % str(ppp_map[interface])
            else:
                wan += ",%s" % interface
        if wan[0] == ',':
            wan = wan[1:]

        network_ip = str()
        for index, octet in enumerate(content[parser_utils.config['CHILLI_NETWORK_MASK']].split('.')):
            if int(octet) < 255:
                network_ip += '.0'
            else:
                network_ip += '.'
                network_ip += content[parser_utils.config['CHILLI_IP']].split('.')[index]
        if network_ip[0] == '.':
            network_ip = network_ip[1:]

        dns = content[parser_utils.config['CHILLI_DNS']].strip()
        if ',' in dns:
            dns = dns.split(',')[0]

        try:
            if set_chilli_configs(
                    wan=wan,
                    lan=content[parser_utils.config['CHILLI_LAN']].strip(),
                    hotspot_network=network_ip.strip(),
                    hotspot_netmask=content[parser_utils.config['CHILLI_NETWORK_MASK']].strip(),
                    listen_ip=content[parser_utils.config['CHILLI_IP']].strip(),
                    dhcp_start=content[parser_utils.config['CHILLI_IP']].strip(),
                    dhcp_mask=content[parser_utils.config['CHILLI_NETWORK_MASK']].strip(),
                    dns=dns
            ):
                response = make_response(200, 'OK')
            else:
                response = make_response(500, 'Error')
        except KeyError as e:
            response = make_response(500, 'KeyError %s' % str(e))

        return response

    # ---------------------------------------------------------------------------

    if method == 'GET':
        data = get_chilli_interfaces()
        if data:
            data['status'] = get_service_status('chilli')
            return json.dumps(data)
        else:
            return make_response(500, 'Error')


################################################################################

# @mod_setting.route('/captive_portal_setting/change_status')
def captive_portal_change_status_view(data):
    status = data.get('status', None)
    response = None
    # print((type(status)))
    if not status:
        response = make_response(400, 'send me status as a query string.')
    elif status.lower() == 'true':
        if change_chilli_status(True):
            response = make_response(200, 'OK')
        else:
            response = make_response(500, 'Error')
    elif status.lower() == 'false':
        if change_chilli_status(False):
            response = make_response(200, 'OK')
        else:
            response = make_response(500, 'Error')
    else:
        response = make_response(400, 'status must be True or False.')

    return response


################################################################################

# @mod_setting.route('/set_update_server', methods=['POST'])
def set_update_server_addr_view(content):
    # content = request.get_json()
    # printLog(request.get_json())
    response = None

    if 'address' in list(content.keys()):
        if config_update_server_address(content['address']):
            response = make_response(200, 'OK')
        else:
            response = make_response(500, 'Error')
    else:
        response = make_response(400, 'address field is nesesary.')

    return response
