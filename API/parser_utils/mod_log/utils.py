from psycopg2.extensions import AsIs

import parser_utils.config
from parser_utils import logger, connect_to_db


def get_user_login_history(username):
    con = next(connect_to_db())
    if not con: return list()
    cursor = con.cursor()
    try:
        cursor.execute("SELECT username,reply,authdate,reply_message FROM \
            %s WHERE username=%s",
                       (AsIs(parser_utils.config['postauth_table']), username)
                       )
    except Exception as e:
        logger.error(str(e))
        con.rollback()
        return None

    data = list()
    for row in cursor.fetchall():
        data.append({
            'username': row[0],
            'reply': 'Accept' if row[1] == "Access-Accept" else 'Reject',
            'datetime': row[2].strftime('%Y-%m-%d %H:%M:%S'),
            'message': row[3] if row[3] else 'Authentication failed!'
        })

    return data
