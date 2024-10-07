import json

from parser_utils import make_response
from .utils import *


# mod_l7 = Blueprint('mod_l7', __name__, url_prefix='/l7')


################################################################################

# @mod_l7.route('/top_app')
def top_app_per_user_view(request):
    per_key = request.args.get('per_key', None)
    per_value = request.args.get('per_value', None)
    limit = request.args.get('limit', '0')
    period = request.args.get('period', None)

    if not limit.isdigit():
        return make_response(400, 'limit must be a an integer')

    measurement = convert_period_to_measurement(period)
    if not measurement:
        return make_response(400, 'period is wrong!')

    limit = int(limit)
    if not period:
        response = make_response(400,
                                 'Send period as query string.')
    elif per_key not in ('interface', 'user', None, ''):
        response = make_response(400, 'per_key must be interface or user.')
    elif limit != 0 and limit < 1:
        response = make_response(400, 'limit must not be little than 1.')
    else:
        if per_key and per_value:
            if per_key == 'interface' and per_value == 'all':
                result = get_data(measurement, 'app')
            else:
                result = get_data(measurement, 'app',
                                  {'field': per_key, 'value': per_value})

        if limit:
            result = result[:limit]
        response = make_response(json.dumps(result), mimetype='application/json')

    return response


################################################################################

# @mod_l7.route('/top_users_per_app')
def top_users_per_app_view(request):
    app = request.args.get('app', None)
    limit = request.args.get('limit', '0')
    period = request.args.get('period', None)

    if not limit.isdigit():
        return make_response(400, 'limit must be a an integer')

    measurement = convert_period_to_measurement(period)
    if not measurement:
        return make_response(400, 'period is wrong!')

    limit = int(limit)
    if not all([app, period]):
        response = make_response(400,
                                 'Send app and period as query string.')
    elif limit != 0 and limit < 1:
        response = make_response(400, 'limit must not be little than 1.')
    else:
        app = app.lower()
        result = get_data(measurement, 'user',
                          {'field': 'app', 'value': app})
        if limit:
            result = result[:limit]
        response = make_response(json.dumps(result), mimetype='application/json')

    return response
