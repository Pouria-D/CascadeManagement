import sys
from datetime import datetime, timedelta

from psycopg2.extensions import AsIs

from parser_utils import connect_to_db
from parser_utils.config import config

sys.path.append(config['FW_MIDDDLEWARE_PATH'])


###############################################################################

def get_policy_usage_latest(policy_id=None, day=None, hour=None, last_hour=False):
    now = datetime.now()

    query_data = []
    if day:
        src_date = now - timedelta(days=day)
        # remove hour and minute and  ...
        query_data.append((datetime(src_date.year, src_date.month, src_date.day), \
                           'new_policy_log_daily'))

        query_data.append((datetime(now.year, now.month, now.day), \
                           'new_policy_log_hourly'))

        query_data.append((datetime(now.year, now.month, now.day, now.hour), \
                           'new_policy_log_min'))

    elif hour:
        src_time = now - timedelta(hours=hour)

        query_data.append((datetime(src_time.year, src_time.month, src_time.day, \
                                    src_time.hour), 'new_policy_log_hourly'))

        query_data.append((datetime(now.year, now.month, now.day, now.hour), \
                           'new_policy_log_min'))

    elif last_hour:
        src_time = now - timedelta(hours=1)
        query_data.append((datetime(src_time.year, src_time.month, src_time.day, \
                                    src_time.hour, src_time.minute), 'new_policy_log_min'))

    else:
        return None

    data = {'megabytes': 0, 'megapkts': 0}
    con = next(connect_to_db())
    if not con: return data
    cursor = con.cursor()

    for q in query_data:
        cursor.execute("SELECT SUM(bytes), SUM(packets) FROM %s \
            WHERE datetime >= %s AND policy_id=%s", (AsIs(q[1]), q[0], policy_id))

        result = cursor.fetchone()

        if result[0] == None:
            data['megabytes'] += 0
        else:
            data['megabytes'] += round(float(result[0]) / 1000000.0, 2)

        if result[1] == None:
            data['megapkts'] += 0
        else:
            data['megapkts'] += round(float(result[1]) / 1000000.0, 2)

    return data


def get_policy_usage_from_to(policy_id=None, src_date=None, dst_date=None):
    if not policy_id or not src_date or not dst_date:
        return None

    dst_date = dst_date + timedelta(days=1)

    data = {'megabytes': 0, 'megapkts': 0}
    con = next(connect_to_db())
    if not con: return data
    cursor = con.cursor()
    cursor.execute("SELECT SUM(bytes), SUM(packets) FROM new_policy_log_daily \
        WHERE policy_id=%s AND datetime >= %s AND datetime<= %s", \
                   (policy_id, src_date, dst_date))
    result = cursor.fetchone()
    cursor.close()

    if result[0] == None:
        data['megabytes'] = 0
    else:
        data['megabytes'] = result[0]

    if result[1] == None:
        data['megapkts'] = 0
    else:
        data['megapkts'] = result[1]

    return data
