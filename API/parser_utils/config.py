config = {
    'SERVER_IP': '0.0.0.0',
    'PORT': 20001,

    'DEBUG': True,
    'TEST': False,

    'GROUP_1_PREFIX': 'ngfw_',

    'TEST_DATABASE_NAME': 'parser_test',
    'DATABASE_ROOT_USERNAME': 'postgres',
    'DATABASE_ROOT_PASSWORD': 'toor',

    'WAN_INTERFACE': 'enp3s2',
    'IPPOLL_TABLE': 'radippool',
    'POLICY_TABLE': "policy_fw",
    'ROUTING_TABLE': "routing",
    'MWLINK_TABLE': "multiwan_data",
    'QOS_POLICY_TABLE': "policy_qos",
    'QOS_GENERAL_CONFIG_TABLE': "qos_general_config",
    'QOS_SHAPER_TABLE': "traffic_shapers",
    'MAC_AUTH_TABLE': 'mac_auth',
    'LOG_ANALYZER_ADDR': 'http://0.0.0.0:20005/',

    'POLICY_ID': "policy_id",
    'POLICY_ACTION': "action",
    'POLICY_USERS': "users",
    'POLICY_GROUPS': "groups",
    'POLICY_SRC': "src",
    'POLICY_DST': "dst",
    'POLICY_NAT': "nat",
    'POLICY_LOG': "log",
    'POLICY_ORDER': "policy_order",
    'POLICY_SCHEDULE': "schedule",
    'POLICY_SERVICES': "services",
    'POLICY_STATUS': 'enabled',

    'PROFILE_ATTRIBUTES_U': 'attributes',
    'PROFILE_ATTRIBUTE_U': 'attribute',
    'PROFILE_ATTR_VALUE_U': 'value',
    'PROFILE_USERNAME_U': 'username',
    'PROFILE_GROUPNAME_U': 'groupname',
    'PROFILE_GROUP_LIST_U': 'groups',
    'PROFILE_PRIORITY_U': 'priority',
    'PROFILE_MAC_AUTH_U': 'mac_auth',
    'PROFILE_MAC_U': 'mac',
    'PROFILE_MAC_FORCE_U': 'force_mac_auth',
    'PROFILE_FORCE_LOGOUT_U': 'force_logout',
    'PROFILE_ATTRIBUTES_G': 'attributes',
    'PROFILE_ATTRIBUTE_G': 'attribute',
    'PROFILE_ATTR_VALUE_G': 'value',
    'PROFILE_GROUPNAME_G': 'groupname',
    'PROFILE_FORCE_LOGOUT_G': 'force_logout',

    'QOS_POLICY_ID': 'policy_id',
    'QOS_POLICY_ORDER': 'policy_order',
    'QOS_POLICY_SCHEDULE': 'schedule',
    'QOS_POLICY_USERS': 'users',
    'QOS_POLICY_GROUPS': 'groups',
    'QOS_POLICY_SRC': 'src',
    'QOS_POLICY_DST': 'dst',
    'QOS_POLICY_SERVICES': 'services',
    'QOS_POLICY_INTERFACES': 'interfaces',
    'QOS_POLICY_SHAPER_ID': 'shaper',
    'QOS_POLICY_RVS_SHAPER': 'reverse_shaper',
    'QOS_POLICY_STATUS': 'enabled',

    'QOS_SHAPER_ID': 'shaper_id',
    'QOS_SHAPER_GUARANTEED_BW': 'guaranteed_bandwidth',
    'QOS_SHAPER_MAX_BW': 'max_bandwidth',
    'QOS_SHAPER_PRIORITY': 'priority',
    'QOS_SHAPER_APPLY_TYPE': 'apply_type',

    'QOS_GC_WAN': 'wan_interface',
    'QOS_GC_MAX_BW_DOWNLOAD': 'max_bandwidth_download',
    'QOS_GC_MAX_BW_UPLOAD': 'max_bandwidth_upload',
    'QOS_GC_GUARANTEED_BW_DOWNLOAD': 'guaranteed_bandwidth_download',
    'QOS_GC_GUARANTEED_BW_UPLOAD': 'guaranteed_bandwidth_upload',
    'QOS_GC_ENABLE': 'enable',

    'CHILLI_WAN': 'wan',
    'CHILLI_LAN': 'lan',
    'CHILLI_NETWORK_MASK': 'network_mask',
    'CHILLI_IP': 'ip',
    'CHILLI_DNS': 'dns',

    'REDIS_HOST': "localhost",
    'REDIS_PORT': 6379,
    'REDIS_DB': 0,

    'LSBLK_FILE_ADDR': '/tmp/lsblk_tmp',

    'ROOTRUNER_PATH': 'http://127.0.0.1:5000/run',
    'ROOTRUNER_ID': '199e1682-6329-4255-ba06-10d51be4e1b9',

    'NETWORK_IF_CONFIG_PATH': '/home/master/workspace/NIC_BW_COLLECTOR/config',

    'UPDATE_MANAGER': 'http://127.0.0.1:20007/',

    'CHILLI_OLD_CONFIG': '/etc/chilli/old_config',

    'MWLINK_ADDR': '/home/master/workspace/MWLINK',
    'DNSCP_ADDR': '/home/master/workspace',
    'TC_MIDDDLEWARE_PATH': '/home/master/workspace/MWQOS',
    'FW_MIDDDLEWARE_PATH': '/etc/freeradius/mods-config/python',

    'UI_PATH': "/usr/local/src/UI/",
    'BACKUP_PATH': "/home/master/backups",
    'L7_DB': 'l7',

    'IP_WHITE_LIST': 'ip_white_list'

}