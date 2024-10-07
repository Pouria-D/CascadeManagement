from parser_utils import logger, influx_client, printLog


###############################################################################

def convert_period_to_measurement(period):
    '''
        This function converts REST API parameter to measurement name.
    '''

    if period == '1Q':
        return 'l7_log'
    elif period == '1H':
        return 'l7_log_hourly'
    elif period == '1D':
        return 'l7_log_daily'
    elif period == '1M':
        return 'l7_log_monthly'


###############################################################################

def get_data(measurement, group_by, where=dict()):
    '''
        This function takes measurement name, "GROUP BY" and "WHERE" fields
        and queries on influxdb and returns the result after sorting it.
        schema of return data: [{'field': x:str, 'traffic': y:int}]
    '''

    result = list()

    if group_by not in ('app', 'user'):
        logger.error("group_by can not be %s" % group_by)
        return False

    if where and 'field' in where and 'value' in where:
        query_where_part = 'where "%s" = \'%s\'' % \
                           (where['field'], where['value'])
    else:
        query_where_part = ''

    query = 'select sum(value) from %s %s group by "%s"' % \
            (measurement, query_where_part, group_by)
    printLog(query)
    fetched_data = influx_client.query(query)
    for row in list(fetched_data.items()):
        for x in row[1]:
            result.append({
                'field': row[0][1][group_by],
                "traffic": int(x['sum']) / 1000.0
            })

    result = sorted(result, key=lambda k: -k['traffic'])
    return result

###############################################################################
