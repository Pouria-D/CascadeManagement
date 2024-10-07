from psycopg2.extensions import AsIs
from psycopg2.extras import DictCursor

import parser_utils.config
from parser_utils import connect_to_db, logger


###############################################################################

def add_user(content, ps_con=None, commit=True):
    if ps_con == None:
        con = next(connect_to_db())
        if not con: return 0
    else:
        con = ps_con

    cursor = con.cursor()

    cursor.execute("INSERT INTO %s (username, groupname, priority) VALUES \
        (%s, %s, %s)", (AsIs(parser_utils.config['usergroup_table']), \
                        content[parser_utils.config['PROFILE_USERNAME_U']], \
                        parser_utils.config['GROUP_1_PREFIX'] + content[parser_utils.config['PROFILE_USERNAME_U']], 1))

    if parser_utils.config['PROFILE_ATTRIBUTES_U'] in list(content.keys()) and content[
        parser_utils.config['PROFILE_ATTRIBUTES_U']]:
        group_content = {parser_utils.config['PROFILE_GROUPNAME_G']: \
                             parser_utils.config['GROUP_1_PREFIX'] + content[parser_utils.config['PROFILE_USERNAME_U']], \
                         parser_utils.config['PROFILE_ATTRIBUTES_G']: content[
                             parser_utils.config['PROFILE_ATTRIBUTES_U']]}

        if not add_group(group_content, ps_con=con, commit=False):
            return 0

    if parser_utils.config['PROFILE_GROUP_LIST_U'] in list(content.keys()) and content[
        parser_utils.config['PROFILE_GROUP_LIST_U']]:
        for group in content[parser_utils.config['PROFILE_GROUP_LIST_U']]:
            try:
                half_query = 'INSERT INTO %s ' % parser_utils.config['usergroup_table']
                cursor.execute(half_query + '(username, groupname, priority) \
                    VALUES (%s, %s, %s)', (content[parser_utils.config['PROFILE_USERNAME_U']], \
                                           group[parser_utils.config['PROFILE_GROUPNAME_U']],
                                           group[parser_utils.config['PROFILE_PRIORITY_U']] + 1))
            except Exception as e:
                logger.error(str(e))
                con.rollback()
                return 0

    if parser_utils.config['PROFILE_MAC_AUTH_U'] in list(content.keys()) and content[
        parser_utils.config['PROFILE_MAC_AUTH_U']]:
        for mac_auth_record in content[parser_utils.config['PROFILE_MAC_AUTH_U']]:
            try:
                half_query = 'INSERT INTO %s ' % parser_utils.config['MAC_AUTH_TABLE']
                cursor.execute(half_query + '(mac, username, force_mac_auth) \
                    VALUES (%s, %s, %s)', (mac_auth_record[parser_utils.config['PROFILE_MAC_U']], \
                                           content[parser_utils.config['PROFILE_USERNAME_U']], \
                                           mac_auth_record[parser_utils.config['PROFILE_MAC_FORCE_U']]))
            except Exception as e:
                logger.error(str(e))
                con.rollback()
                if 'ERROR:  duplicate key value violates unique constraint' \
                        in str(e.pgerror) and 'already exists' in str(e.pgerror):
                    return -2
                else:
                    return 0

    if commit:
        try:
            con.commit()
        except Exception as e:
            con.rollback()
            logger.error(str(e))
            return -1

    return 1


###############################################################################

def delete_user(username, ps_con=None, commit=True):
    if ps_con == None:
        con = next(connect_to_db())
        if not con: return False
    else:
        con = ps_con

    cursor = con.cursor()
    status = False

    try:
        half_query = 'DELETE FROM %s ' % parser_utils.config['authcheck_table']
        cursor.execute(half_query + 'WHERE username=%s', \
                       (username,))

        if cursor.statusmessage != 'DELETE 0':
            status = True

        half_query = 'DELETE FROM %s ' % parser_utils.config['MAC_AUTH_TABLE']
        cursor.execute(half_query + 'WHERE username=%s', \
                       (username,))

        if cursor.statusmessage != 'DELETE 0':
            status = True

        half_query = 'DELETE FROM %s ' % parser_utils.config['usergroup_table']
        cursor.execute(half_query + 'WHERE username=%s', \
                       (username,))

        if cursor.statusmessage != 'DELETE 0':
            status = True

        if commit:
            cursor.execute('DELETE FROM %s WHERE username=%s',
                           (AsIs(parser_utils.config['acct_table']), username))

        if cursor.statusmessage != 'DELETE 0':
            status = True

        delete_group(parser_utils.config['GROUP_1_PREFIX'] + username, ps_con=con, commit=False, delete_users=True)

    except Exception as e:
        logger.error(str(e))
        con.rollback()
        return False

    if commit:
        try:
            con.commit()
        except:
            con.rollback()
            return False

    if status == True:
        return 'Deleted'
    else:
        return 'Not Found'


###############################################################################

def delete_group(groupname, ps_con=None, commit=True, delete_users=True):
    if ps_con == None:
        con = next(connect_to_db())
        if not con: return -1
    else:
        con = ps_con

    if not delete_exceeded_quota(groupname, con):
        return False

    cursor = con.cursor()
    status = False

    try:
        half_query = 'DELETE FROM %s ' % parser_utils.config['groupcheck_table']
        cursor.execute(half_query + 'WHERE groupname=%s', \
                       (groupname,))
        if cursor.statusmessage != 'DELETE 0':
            status = True

        half_query = 'DELETE FROM %s ' % parser_utils.config['groupreply_table']
        cursor.execute(half_query + 'WHERE groupname=%s', \
                       (groupname,))
        if cursor.statusmessage != 'DELETE 0':
            status = True

        if delete_users:
            half_query = 'DELETE FROM %s ' % parser_utils.config['usergroup_table']
            cursor.execute(half_query + 'WHERE groupname=%s', \
                           (groupname,))

    except Exception as e:
        con.rollback()
        return -1

    if commit:
        try:
            con.commit()
        except  Exception as e:
            con.rollback()
            return -1

    if status:
        return 1
    elif not status:
        return 0


###############################################################################

def add_group(content, ps_con=None, commit=True):
    if ps_con == None:
        con = next(connect_to_db())
        if not con: return False
    else:
        con = ps_con

    attributes = add_exceeded_quota(content[parser_utils.config['PROFILE_GROUPNAME_G']],
                                    content[parser_utils.config['PROFILE_ATTRIBUTES_G']], con)
    if attributes == False:
        return False

    cursor = con.cursor()
    for attr in attributes:
        try:
            half_query = 'INSERT INTO %s ' % parser_utils.config['groupcheck_table']
            cursor.execute(half_query + "(groupname, attribute, op, value) \
                VALUES (%s, %s, ':=', %s)",
                           (content[parser_utils.config['PROFILE_GROUPNAME_G']],
                            attr[parser_utils.config['PROFILE_ATTRIBUTE_G']], \
                            attr[parser_utils.config['PROFILE_ATTR_VALUE_G']]))
        except Exception as e:
            logger.error(str(e))
            con.rollback()
            return False

    try:
        half_query = 'INSERT INTO %s ' % parser_utils.config['groupreply_table']
        cursor.execute(half_query + "(groupname, attribute, op, value) \
            VALUES (%s, %s, ':=', %s)", (content[parser_utils.config['PROFILE_GROUPNAME_G']], \
                                         'Fall-Through', 'Yes'))

    except Exception as e:
        logger.error(str(e))
        con.rollback()
        return False

    if commit:
        try:
            con.commit()
        except Exception as e:
            con.rollback()
            logger.error(str(e))
            return False

    return True


###############################################################################

def check_user_existance(username):
    con = next(connect_to_db())
    if not con: return False
    cursor = con.cursor()
    result = None

    try:
        cursor.execute("SELECT username FROM %s WHERE username = %s LIMIT 1", \
                       (AsIs(parser_utils.config['usergroup_table']), username))
        result = cursor.fetchone()
    except Exception as e:
        logger.error(str(e))
        con.rollback()

    if result:
        return True
    return False


###############################################################################

def check_group_existance(groupname):
    con = next(connect_to_db())
    if not con: return False
    cursor = con.cursor()
    result = None

    try:
        cursor.execute("SELECT groupname FROM %s WHERE groupname = %s LIMIT 1", \
                       (AsIs(parser_utils.config['usergroup_table']), groupname))

        result = cursor.fetchone()

        if not result:
            cursor.execute("SELECT groupname FROM %s WHERE groupname = %s LIMIT 1", \
                           (AsIs(parser_utils.config['groupcheck_table']), groupname))
            result = cursor.fetchone()

    except Exception as e:
        logger.error(str(e))
        con.rollback()

    if result:
        return True
    return False


###############################################################################

def get_quota_limitation(username):
    con = next(connect_to_db())
    if not con: return {}
    cursor = con.cursor()

    # define what we need!
    needs = ['Max-Download-Daily', 'Max-Upload-Daily', 'Max-Download-Weekly',
             'Max-Upload-Weekly', 'Max-Download-Monthly', 'Max-Upload-Monthly']

    try:
        # get data from database (includes all quota data for a user and it's groups)
        cursor.execute("SELECT %s.attribute, %s.value \
            FROM %s LEFT JOIN %s ON %s.groupname = %s.groupname WHERE username=%s \
            AND attribute IN %s ORDER BY priority",
                       (AsIs(parser_utils.config['groupcheck_table']), AsIs(parser_utils.config['groupcheck_table']),
                        AsIs(parser_utils.config['groupcheck_table']), AsIs(parser_utils.config['usergroup_table']),
                        AsIs(parser_utils.config['groupcheck_table']), AsIs(parser_utils.config['usergroup_table']),
                        username, AsIs(tuple(needs))))

        result = cursor.fetchall()
    except Exception as e:
        logger.error(str(e))
        con.rollback()

    data = {}
    for record in result:
        if record[0] in needs:
            data[record[0]] = record[1]
            needs.remove(record[0])

        if not needs:
            break

    # set 'unlimited' for keys that had not value
    if needs:
        for x in needs:
            data[x] = 'unlimited'

    return data


###############################################################################

def get_group_list():
    con = next(connect_to_db())
    if not con: return set()
    cursor = con.cursor()

    groups = set()

    try:
        cursor.execute("SELECT groupname FROM %s", (AsIs(parser_utils.config['usergroup_table']),))
        result = cursor.fetchall()
        for record in result:
            if record[0][:5] != 'ngfw_':
                groups.add(record[0])

        cursor.execute("SELECT groupname FROM %s", (AsIs(parser_utils.config['groupcheck_table']),))
        result = cursor.fetchall()
        for record in result:
            if record[0][:5] != 'ngfw_':
                groups.add(record[0])
    except Exception as e:
        logger.error(str(e))
        con.rollback()

    return groups


###############################################################################

def get_user_list():
    con = next(connect_to_db())
    if not con: return set()
    cursor = con.cursor()
    users = set()

    try:
        cursor.execute("SELECT username FROM %s", (AsIs(parser_utils.config['usergroup_table']),))
        result = cursor.fetchall()
        for record in result:
            users.add(record[0])

    except Exception as e:
        logger.error(str(e))
        con.rollback()

    return users


###############################################################################

def get_user_mac_auth_data(username):
    con = next(connect_to_db())
    if not con: return list()
    cursor = con.cursor(cursor_factory=DictCursor)

    try:
        cursor.execute("SELECT mac, force_mac_auth FROM %s WHERE username=%s", \
                       (AsIs(parser_utils.config['MAC_AUTH_TABLE']), username))
        result = cursor.fetchall()
    except Exception as e:
        logger.error(str(e))
        con.rollback()

    old_MACs = list()
    for record in result:
        old_MACs.append(dict(record))

    return old_MACs


###############################################################################

def change_username(old_username, new_username):
    '''
        Change username in profile, policy_fw and policy_qos tables.
    '''

    changed = False

    con = next(connect_to_db())
    if not con: return False
    cursor = con.cursor()

    try:
        cursor.execute('UPDATE %s SET groupname=%s WHERE username=%s AND \
            groupname=%s', (AsIs(parser_utils.config['usergroup_table']),
                            parser_utils.config['GROUP_1_PREFIX'] + new_username, old_username,
                            parser_utils.config['GROUP_1_PREFIX'] + old_username)
                       )

        cursor.execute('UPDATE %s SET username=%s WHERE username=%s',
                       (AsIs(parser_utils.config['usergroup_table']), new_username, old_username)
                       )

        cursor.execute('UPDATE %s SET groupname=%s WHERE groupname=%s',
                       (AsIs(parser_utils.config['groupcheck_table']),
                        parser_utils.config['GROUP_1_PREFIX'] + new_username,
                        parser_utils.config['GROUP_1_PREFIX'] + old_username)
                       )

        cursor.execute('UPDATE %s SET groupname=%s WHERE groupname=%s',
                       (AsIs(parser_utils.config['groupreply_table']),
                        parser_utils.config['GROUP_1_PREFIX'] + new_username,
                        parser_utils.config['GROUP_1_PREFIX'] + old_username)
                       )

        cursor.execute('UPDATE %s SET username=%s WHERE username=%s',
                       (AsIs(parser_utils.config['MAC_AUTH_TABLE']), new_username, old_username)
                       )

        cursor.execute('UPDATE %s SET username=%s WHERE username=%s',
                       (AsIs(parser_utils.config['acct_table']), new_username, old_username)
                       )

        con.commit()
        changed = True
    except Exception as e:
        logger.error(str(e))
        con.rollback()
    finally:
        cursor.close()

    return changed


###############################################################################

def change_groupname(old_groupname, new_groupname):
    '''
        Change groupname in profile, policy_fw and policy_qos tables.
    '''

    changed = False

    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor()

    try:
        cursor.execute('UPDATE %s SET groupname=%s WHERE groupname=%s',
                       (AsIs(parser_utils.config['usergroup_table']), new_groupname, old_groupname)
                       )

        cursor.execute('UPDATE %s SET groupname=%s WHERE groupname=%s',
                       (AsIs(parser_utils.config['groupcheck_table']), new_groupname, old_groupname)
                       )

        cursor.execute('UPDATE %s SET groupname=%s WHERE groupname=%s',
                       (AsIs(parser_utils.config['groupreply_table']), new_groupname, old_groupname)
                       )

        con.commit()
        changed = True
    except Exception as e:
        logger.error(str(e))
        con.rollback()
    finally:
        cursor.close()

    return changed


###############################################################################

def change_user_password(user, new_password, old_password):
    '''
        Change password.
    '''
    status = None
    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor()

    try:
        cursor.execute("""UPDATE %s SET value=%s WHERE \
            attribute='Cleartext-Password' AND groupname=%s AND value=%s""",
                       (AsIs(parser_utils.config['groupcheck_table']), new_password, 'ngfw_' + user,
                        old_password)
                       )
        con.commit()
        if cursor.rowcount > 0:
            status = 1
        else:
            status = 2
    except Exception as e:
        logger.error(str(e))
        con.rollback()
        status = 3
    finally:
        cursor.close()

    return status


###############################################################################

def get_online_user_macs(username):
    '''
        This function takes a username and tries to get his IP and MAC address
        (just online devices)
        Returns a list of dictionaries  with this schema:
        {'MAC': mac_address, 'IP': ip_address}
        If he has no online device an empthy list will return.
    '''

    con = next(connect_to_db())
    if not con: return None
    cursor = con.cursor()

    result = list()
    try:
        cursor.execute("""SELECT callingstationid,framedipaddress FROM %s WHERE \
            acctstoptime IS NULL AND username=%s""",
                       (AsIs(parser_utils.config['acct_table']), username)
                       )
        for row in cursor.fetchall():
            result.append({'MAC': row[0], 'IP': row[1]})
    except Exception as e:
        logger.error(str(e))
        con.rollback()
    finally:
        cursor.close()

    return result


###############################################################################

def add_exceeded_quota(groupname, attributes, con):
    exceeded_flag = False

    d_bw = [x for x in attributes if x['attribute'] == 'Exceeded-Quota-Download']
    exceeded_traffic_limit = []
    if d_bw:
        download_bw = d_bw[0]['value']
        if not download_bw:
            download_bw = None
        else:
            download_bw = float(download_bw) * 1000
        attributes.remove(d_bw[0])

        if download_bw:
            d_daily = [x for x in attributes if x['attribute'] == 'Max-Download-Daily']
            if d_daily:
                row = (groupname, d_daily[0]['value'], 'day', 'acctinputoctets')
                exceeded_traffic_limit.append(row)
                attributes.remove(d_daily[0])

            d_weekly = [x for x in attributes if x['attribute'] == 'Max-Download-Weekly']
            if d_weekly:
                row = (groupname, d_weekly[0]['value'], 'week', 'acctinputoctets')
                exceeded_traffic_limit.append(row)
                attributes.remove(d_weekly[0])

            d_monthly = [x for x in attributes if x['attribute'] == 'Max-Download-Monthly']
            if d_monthly:
                row = (groupname, d_monthly[0]['value'], 'month', 'acctinputoctets')
                exceeded_traffic_limit.append(row)
                attributes.remove(d_monthly[0])
    else:
        download_bw = None

    u_bw = [x for x in attributes if x['attribute'] == 'Exceeded-Quota-Upload']
    if u_bw:
        upload_bw = u_bw[0]['value']
        if not upload_bw:
            upload_bw = None
        else:
            upload_bw = float(upload_bw) * 1000
        attributes.remove(u_bw[0])

        if upload_bw:
            u_daily = [x for x in attributes if x['attribute'] == 'Max-Upload-Daily']
            if u_daily:
                row = (groupname, u_daily[0]['value'], 'day', 'acctoutputoctets')
                exceeded_traffic_limit.append(row)
                attributes.remove(u_daily[0])

            u_weekly = [x for x in attributes if x['attribute'] == 'Max-Upload-Weekly']
            if u_weekly:
                row = (groupname, u_weekly[0]['value'], 'week', 'acctoutputoctets')
                exceeded_traffic_limit.append(row)
                attributes.remove(u_weekly[0])

            u_monthly = [x for x in attributes if x['attribute'] == 'Max-Upload-Monthly']
            if u_monthly:
                row = (groupname, u_monthly[0]['value'], 'month', 'acctoutputoctets')
                exceeded_traffic_limit.append(row)
                attributes.remove(u_monthly[0])

    else:
        upload_bw = None

    cursor = con.cursor()
    try:
        # print([download_bw, upload_bw])
        if any([download_bw, upload_bw]):
            cursor.execute("INSERT INTO %s (groupname, \
                download_exceeded_bandwidth, upload_exceeded_bandwidth) VALUES \
                (%s,%s,%s)", (AsIs('userexceededbandwidth'), groupname,
                              download_bw, upload_bw))

        if exceeded_traffic_limit:
            for i in exceeded_traffic_limit:
                cursor.execute("INSERT INTO %s (groupname, quota, interval, \
                    type) VALUES (%s,%s,%s,%s)", (AsIs('exceeded_quota_bw'),
                                                  i[0], i[1], i[2], i[3]))
        con.commit()
    except Exception as e:
        con.rollback()
        logger.error(e)
        return False

    return attributes


###############################################################################

def delete_exceeded_quota(groupname, con):
    cursor = con.cursor()

    try:
        cursor.execute("DELETE FROM %s WHERE groupname=%s",
                       (AsIs('userexceededbandwidth'), groupname))
        cursor.execute("DELETE FROM %s WHERE groupname=%s",
                       (AsIs('exceeded_quota_bw'), groupname))
        con.commit()
    except Exception as e:
        con.rollback()
        logger.error(e)
        return False

    return True
