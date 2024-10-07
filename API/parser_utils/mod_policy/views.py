import json
from datetime import datetime
from operator import itemgetter

from parser_utils import make_response, connect_to_db
from .utils import get_policy_usage_latest, get_policy_usage_from_to


def policy_usage_latest_days(request):
    try:
        result = get_policy_usage_latest(int(request.args.get("policy_id")), day=int(request.args.get("day")))
    except ValueError:
        return make_response(400, "policy_id or day value is wrong. They must be integer")

    if result:
        return json.dumps(result)
    else:
        return json.dumps({})


def policy_usage_from_to(request):
    try:
        from_date = datetime.strptime(request.args.get("from"), '%Y-%m-%d')
        to_date = datetime.strptime(request.args.get("to"), '%Y-%m-%d')
        result = get_policy_usage_from_to(int(request.args.get("policy_id")), from_date, to_date)
    except ValueError:
        return make_response(400, "'from' or 'to' value is wrong. They must be date")

    if result:
        return json.dumps(result)
    else:
        return json.dumps({})


def policy_usage_latest_hour(id):
    try:
        result = get_policy_usage_latest(policy_id=int(id), last_hour=True)

    except ValueError:
        return make_response(400, "policy_id value is wrong. They must be integer")

    if result:
        return json.dumps(result)
    else:
        return json.dumps({})


def policy_usage_latest_day(id):
    result = get_policy_usage_latest(policy_id=int(id), hour=24)
    return result


def get_top_policies(request):
    con = next(connect_to_db())
    if not con: return list()
    cursor = con.cursor()
    # get list of policy ID from database
    try:
        cursor.execute("SELECT policy_id FROM policy_fw")
    except:
        con.rollback()

    policy_list = [int(x[0]) for x in cursor.fetchall()]
    cursor.close()

    total_result = []
    if request.args.get("interval") == 'month':
        for policy_id in policy_list:
            result = get_policy_usage_latest(policy_id, day=30)
            result['policy_id'] = policy_id
            total_result.append(result)

    elif request.args.get("interval") == 'week':

        for policy_id in policy_list:
            result = get_policy_usage_latest(policy_id, day=7)
            result['policy_id'] = policy_id
            total_result.append(result)

    elif request.args.get("interval") == 'year':
        for policy_id in policy_list:
            result = get_policy_usage_latest(policy_id, day=365)
            result['policy_id'] = policy_id
            total_result.append(result)

    elif request.args.get("interval") == 'day':
        for policy_id in policy_list:
            result = get_policy_usage_latest(policy_id, hour=24)
            result['policy_id'] = policy_id
            total_result.append(result)

    elif request.args.get("interval") == 'hour':
        for policy_id in policy_list:
            result = get_policy_usage_latest(policy_id, last_hour=True)
            result['policy_id'] = policy_id
            total_result.append(result)

    total_result.sort(key=itemgetter(request.args.get("type")))
    total_result = total_result[-int(request.args.get("count")):]
    total_result.reverse()

    return make_response(json.dumps(total_result), mimetype='application/json')
