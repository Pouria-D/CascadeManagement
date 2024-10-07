--
-- PostgreSQL database dump
--

-- Dumped from database version 9.5.4
-- Dumped by pg_dump version 9.5.4

SET statement_timeout = 0;
SET lock_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: radius2; Type: COMMENT; Schema: -; Owner: radius
--

COMMENT ON DATABASE radius2 IS 'exit';


--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


SET search_path = public, pg_catalog;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: app_filter; Type: TABLE; Schema: public; Owner: radius
--

CREATE TABLE app_filter (
    id bigint NOT NULL,
    policy_name character varying(255) NOT NULL,
    acction character varying(255) NOT NULL,
    app character varying(255) NOT NULL,
    fun_layer integer NOT NULL
);


ALTER TABLE app_filter OWNER TO radius;

--
-- Name: app_filter_id_seq; Type: SEQUENCE; Schema: public; Owner: radius
--

CREATE SEQUENCE app_filter_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE app_filter_id_seq OWNER TO radius;

--
-- Name: app_filter_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: radius
--

ALTER SEQUENCE app_filter_id_seq OWNED BY app_filter.id;


--
-- Name: mac_auth; Type: TABLE; Schema: public; Owner: radius
--

CREATE TABLE mac_auth (
    mac character varying(17) NOT NULL,
    username character varying(64) NOT NULL,
    force_mac_auth boolean DEFAULT false NOT NULL
);


ALTER TABLE mac_auth OWNER TO radius;

--
-- Name: nas; Type: TABLE; Schema: public; Owner: radius
--

CREATE TABLE nas (
    id integer NOT NULL,
    nasname text NOT NULL,
    shortname text NOT NULL,
    type text DEFAULT 'other'::text NOT NULL,
    ports integer,
    secret text NOT NULL,
    server text,
    community text,
    description text
);


ALTER TABLE nas OWNER TO radius;

--
-- Name: nas_id_seq; Type: SEQUENCE; Schema: public; Owner: radius
--

CREATE SEQUENCE nas_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE nas_id_seq OWNER TO radius;

--
-- Name: nas_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: radius
--

ALTER SEQUENCE nas_id_seq OWNED BY nas.id;


--
-- Name: policy_fw; Type: TABLE; Schema: public; Owner: radius
--

CREATE TABLE policy_fw (
    policy_id bigint NOT NULL,
    action character varying(6) NOT NULL,
    users json,
    groups json,
    schedule json,
    src json NOT NULL,
    dst json NOT NULL,
    nat json,
    log boolean DEFAULT false,
    policy_order integer NOT NULL,
    services json
);


ALTER TABLE policy_fw OWNER TO radius;

--
-- Name: qos_config; Type: TABLE; Schema: public; Owner: radius
--

CREATE TABLE qos_config (
    id bigint NOT NULL,
    policy_name character varying(256) NOT NULL,
    based_on character varying(256) NOT NULL,
    policy_type character varying(256) NOT NULL,
    priority character varying(256) NOT NULL,
    bandwidth character varying(256) NOT NULL,
    guarantee character varying(256) NOT NULL,
    burstable character varying(256) NOT NULL,
    bandwidth_usage_type character varying(256) NOT NULL,
    dev character varying(256) NOT NULL
);


ALTER TABLE qos_config OWNER TO radius;

--
-- Name: qos_config_id_seq; Type: SEQUENCE; Schema: public; Owner: radius
--

CREATE SEQUENCE qos_config_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE qos_config_id_seq OWNER TO radius;

--
-- Name: qos_config_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: radius
--

ALTER SEQUENCE qos_config_id_seq OWNED BY qos_config.id;


--
-- Name: radacct; Type: TABLE; Schema: public; Owner: radius
--

CREATE TABLE radacct (
    radacctid bigint NOT NULL,
    acctsessionid text NOT NULL,
    acctuniqueid text NOT NULL,
    username text,
    groupname text,
    realm text,
    nasipaddress inet NOT NULL,
    nasportid text,
    nasporttype text,
    acctstarttime timestamp with time zone,
    acctupdatetime timestamp with time zone,
    acctstoptime timestamp with time zone,
    acctinterval bigint,
    acctsessiontime bigint,
    acctauthentic text,
    connectinfo_start text,
    connectinfo_stop text,
    acctinputoctets bigint,
    acctoutputoctets bigint,
    calledstationid text,
    callingstationid text,
    acctterminatecause text,
    servicetype text,
    framedprotocol text,
    framedipaddress inet
);


ALTER TABLE radacct OWNER TO radius;

--
-- Name: radacct_radacctid_seq; Type: SEQUENCE; Schema: public; Owner: radius
--

CREATE SEQUENCE radacct_radacctid_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE radacct_radacctid_seq OWNER TO radius;

--
-- Name: radacct_radacctid_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: radius
--

ALTER SEQUENCE radacct_radacctid_seq OWNED BY radacct.radacctid;


--
-- Name: radcheck; Type: TABLE; Schema: public; Owner: radius
--

CREATE TABLE radcheck (
    id integer NOT NULL,
    username text DEFAULT ''::text NOT NULL,
    attribute text DEFAULT ''::text NOT NULL,
    op character varying(2) DEFAULT '=='::character varying NOT NULL,
    value text DEFAULT ''::text NOT NULL
);


ALTER TABLE radcheck OWNER TO radius;

--
-- Name: radcheck_id_seq; Type: SEQUENCE; Schema: public; Owner: radius
--

CREATE SEQUENCE radcheck_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE radcheck_id_seq OWNER TO radius;

--
-- Name: radcheck_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: radius
--

ALTER SEQUENCE radcheck_id_seq OWNED BY radcheck.id;


--
-- Name: radgroupcheck; Type: TABLE; Schema: public; Owner: radius
--

CREATE TABLE radgroupcheck (
    id integer NOT NULL,
    groupname text DEFAULT ''::text NOT NULL,
    attribute text DEFAULT ''::text NOT NULL,
    op character varying(2) DEFAULT '=='::character varying NOT NULL,
    value text DEFAULT ''::text NOT NULL
);


ALTER TABLE radgroupcheck OWNER TO radius;

--
-- Name: radgroupcheck_id_seq; Type: SEQUENCE; Schema: public; Owner: radius
--

CREATE SEQUENCE radgroupcheck_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE radgroupcheck_id_seq OWNER TO radius;

--
-- Name: radgroupcheck_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: radius
--

ALTER SEQUENCE radgroupcheck_id_seq OWNED BY radgroupcheck.id;


--
-- Name: radgroupdomainpolicy; Type: TABLE; Schema: public; Owner: radius
--

CREATE TABLE radgroupdomainpolicy (
    id bigint NOT NULL,
    groupname character varying(255) NOT NULL,
    domain character varying(255) NOT NULL
);


ALTER TABLE radgroupdomainpolicy OWNER TO radius;

--
-- Name: radgroupdomainpolicy_id_seq; Type: SEQUENCE; Schema: public; Owner: radius
--

CREATE SEQUENCE radgroupdomainpolicy_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE radgroupdomainpolicy_id_seq OWNER TO radius;

--
-- Name: radgroupdomainpolicy_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: radius
--

ALTER SEQUENCE radgroupdomainpolicy_id_seq OWNED BY radgroupdomainpolicy.id;


--
-- Name: radgroupmimetypepolicy; Type: TABLE; Schema: public; Owner: radius
--

CREATE TABLE radgroupmimetypepolicy (
    id bigint NOT NULL,
    groupname character varying(255) NOT NULL,
    mimetype character varying(255) NOT NULL
);


ALTER TABLE radgroupmimetypepolicy OWNER TO radius;

--
-- Name: radgroupmimetypepolicy_id_seq; Type: SEQUENCE; Schema: public; Owner: radius
--

CREATE SEQUENCE radgroupmimetypepolicy_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE radgroupmimetypepolicy_id_seq OWNER TO radius;

--
-- Name: radgroupmimetypepolicy_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: radius
--

ALTER SEQUENCE radgroupmimetypepolicy_id_seq OWNED BY radgroupmimetypepolicy.id;


--
-- Name: radgroupreply; Type: TABLE; Schema: public; Owner: radius
--

CREATE TABLE radgroupreply (
    id integer NOT NULL,
    groupname text DEFAULT ''::text NOT NULL,
    attribute text DEFAULT ''::text NOT NULL,
    op character varying(2) DEFAULT '='::character varying NOT NULL,
    value text DEFAULT ''::text NOT NULL
);


ALTER TABLE radgroupreply OWNER TO radius;

--
-- Name: radgroupreply_id_seq; Type: SEQUENCE; Schema: public; Owner: radius
--

CREATE SEQUENCE radgroupreply_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE radgroupreply_id_seq OWNER TO radius;

--
-- Name: radgroupreply_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: radius
--

ALTER SEQUENCE radgroupreply_id_seq OWNED BY radgroupreply.id;


--
-- Name: radippool; Type: TABLE; Schema: public; Owner: radius
--

CREATE TABLE radippool (
    id bigint NOT NULL,
    pool_name character varying(64) NOT NULL,
    framedipaddress inet NOT NULL,
    nasipaddress character varying(16) DEFAULT ''::character varying NOT NULL,
    pool_key character varying(64) DEFAULT 0 NOT NULL,
    calledstationid character varying(64),
    callingstationid text DEFAULT ''::text NOT NULL,
    expiry_time timestamp(0) without time zone DEFAULT '2017-01-22 14:41:34.750714'::timestamp(0) without time zone NOT NULL,
    username text DEFAULT ''::text
);


ALTER TABLE radippool OWNER TO radius;

--
-- Name: radippool_id_seq; Type: SEQUENCE; Schema: public; Owner: radius
--

CREATE SEQUENCE radippool_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE radippool_id_seq OWNER TO radius;

--
-- Name: radippool_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: radius
--

ALTER SEQUENCE radippool_id_seq OWNED BY radippool.id;


--
-- Name: radpostauth; Type: TABLE; Schema: public; Owner: radius
--

CREATE TABLE radpostauth (
    id bigint NOT NULL,
    username text NOT NULL,
    pass text,
    reply text,
    calledstationid text,
    callingstationid text,
    authdate timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE radpostauth OWNER TO radius;

--
-- Name: radpostauth_id_seq; Type: SEQUENCE; Schema: public; Owner: radius
--

CREATE SEQUENCE radpostauth_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE radpostauth_id_seq OWNER TO radius;

--
-- Name: radpostauth_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: radius
--

ALTER SEQUENCE radpostauth_id_seq OWNED BY radpostauth.id;


--
-- Name: radreply; Type: TABLE; Schema: public; Owner: radius
--

CREATE TABLE radreply (
    id integer NOT NULL,
    username text DEFAULT ''::text NOT NULL,
    attribute text DEFAULT ''::text NOT NULL,
    op character varying(2) DEFAULT '='::character varying NOT NULL,
    value text DEFAULT ''::text NOT NULL
);


ALTER TABLE radreply OWNER TO radius;

--
-- Name: radreply_id_seq; Type: SEQUENCE; Schema: public; Owner: radius
--

CREATE SEQUENCE radreply_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE radreply_id_seq OWNER TO radius;

--
-- Name: radreply_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: radius
--

ALTER SEQUENCE radreply_id_seq OWNED BY radreply.id;


--
-- Name: radusergroup; Type: TABLE; Schema: public; Owner: radius
--

CREATE TABLE radusergroup (
    id integer NOT NULL,
    username text DEFAULT ''::text NOT NULL,
    groupname text DEFAULT ''::text NOT NULL,
    priority integer DEFAULT 0 NOT NULL
);


ALTER TABLE radusergroup OWNER TO radius;

--
-- Name: radusergroup_id_seq; Type: SEQUENCE; Schema: public; Owner: radius
--

CREATE SEQUENCE radusergroup_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE radusergroup_id_seq OWNER TO radius;

--
-- Name: radusergroup_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: radius
--

ALTER SEQUENCE radusergroup_id_seq OWNED BY radusergroup.id;


--
-- Name: tc_class_id; Type: TABLE; Schema: public; Owner: radius
--

CREATE TABLE tc_class_id (
    id bigint NOT NULL,
    id_pool integer NOT NULL,
    in_use smallint NOT NULL
);


ALTER TABLE tc_class_id OWNER TO radius;

--
-- Name: tc_class_id_id_seq; Type: SEQUENCE; Schema: public; Owner: radius
--

CREATE SEQUENCE tc_class_id_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE tc_class_id_id_seq OWNER TO radius;

--
-- Name: tc_class_id_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: radius
--

ALTER SEQUENCE tc_class_id_id_seq OWNED BY tc_class_id.id;


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: radius
--

ALTER TABLE ONLY app_filter ALTER COLUMN id SET DEFAULT nextval('app_filter_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: radius
--

ALTER TABLE ONLY nas ALTER COLUMN id SET DEFAULT nextval('nas_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: radius
--

ALTER TABLE ONLY qos_config ALTER COLUMN id SET DEFAULT nextval('qos_config_id_seq'::regclass);


--
-- Name: radacctid; Type: DEFAULT; Schema: public; Owner: radius
--

ALTER TABLE ONLY radacct ALTER COLUMN radacctid SET DEFAULT nextval('radacct_radacctid_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: radius
--

ALTER TABLE ONLY radcheck ALTER COLUMN id SET DEFAULT nextval('radcheck_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: radius
--

ALTER TABLE ONLY radgroupcheck ALTER COLUMN id SET DEFAULT nextval('radgroupcheck_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: radius
--

ALTER TABLE ONLY radgroupreply ALTER COLUMN id SET DEFAULT nextval('radgroupreply_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: radius
--

ALTER TABLE ONLY radpostauth ALTER COLUMN id SET DEFAULT nextval('radpostauth_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: radius
--

ALTER TABLE ONLY radreply ALTER COLUMN id SET DEFAULT nextval('radreply_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: radius
--

ALTER TABLE ONLY radusergroup ALTER COLUMN id SET DEFAULT nextval('radusergroup_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: radius
--

ALTER TABLE ONLY tc_class_id ALTER COLUMN id SET DEFAULT nextval('tc_class_id_id_seq'::regclass);


--
-- Data for Name: app_filter; Type: TABLE DATA; Schema: public; Owner: radius
--



--
-- Name: app_filter_id_seq; Type: SEQUENCE SET; Schema: public; Owner: radius
--

SELECT pg_catalog.setval('app_filter_id_seq', 1, false);


--
-- Data for Name: mac_auth; Type: TABLE DATA; Schema: public; Owner: radius
--

INSERT INTO mac_auth (mac, username, force_mac_auth) VALUES ('08-00-27-C2-EB-95', 'a1', false);


--
-- Data for Name: nas; Type: TABLE DATA; Schema: public; Owner: radius
--



--
-- Name: nas_id_seq; Type: SEQUENCE SET; Schema: public; Owner: radius
--

SELECT pg_catalog.setval('nas_id_seq', 1, false);


--
-- Data for Name: policy_fw; Type: TABLE DATA; Schema: public; Owner: radius
--

INSERT INTO policy_fw (policy_id, action, users, groups, schedule, src, dst, nat, log, policy_order, services) VALUES (105, 'ACCEPT', 'null', 'null', 'null', '{"src_network": [], "src_interfaces": null}', '{"dst_interfaces": null, "dst_network": []}', 'null', false, 7, '{"l7": ["ssl"], "l4": []}');


--
-- Data for Name: qos_config; Type: TABLE DATA; Schema: public; Owner: radius
--



--
-- Name: qos_config_id_seq; Type: SEQUENCE SET; Schema: public; Owner: radius
--

SELECT pg_catalog.setval('qos_config_id_seq', 1, false);


--
-- Data for Name: radacct; Type: TABLE DATA; Schema: public; Owner: radius
--

INSERT INTO radacct (radacctid, acctsessionid, acctuniqueid, username, groupname, realm, nasipaddress, nasportid, nasporttype, acctstarttime, acctupdatetime, acctstoptime, acctinterval, acctsessiontime, acctauthentic, connectinfo_start, connectinfo_stop, acctinputoctets, acctoutputoctets, calledstationid, callingstationid, acctterminatecause, servicetype, framedprotocol, framedipaddress) VALUES (596, '58ad100a00000001', '3a87265c66bb4eb11143331b41026c76', 'a1', NULL, NULL, '192.168.1.1', '00000001', 'Wireless-802.11', '2017-02-22 08:14:13+03:30', '2017-02-22 08:19:13+03:30', NULL, 300, 2101, '', '', NULL, 416517, 80439, '0A-00-27-00-00-00', '08-00-27-C2-EB-95', NULL, '', '', '192.168.1.5');
INSERT INTO radacct (radacctid, acctsessionid, acctuniqueid, username, groupname, realm, nasipaddress, nasportid, nasporttype, acctstarttime, acctupdatetime, acctstoptime, acctinterval, acctsessiontime, acctauthentic, connectinfo_start, connectinfo_stop, acctinputoctets, acctoutputoctets, calledstationid, callingstationid, acctterminatecause, servicetype, framedprotocol, framedipaddress) VALUES (581, '58ac0bb900000001', '3b03a15ea2043146381d94fc184db9d8', 'a1', NULL, NULL, '192.168.1.1', '00000001', 'Wireless-802.11', '2017-02-21 13:13:21+03:30', '2017-02-21 13:16:11+03:30', '2017-02-21 13:16:11+03:30', NULL, 169, '', '', '', 0, 2947, '0A-00-27-00-00-00', '08-00-27-C2-EB-95', 'User-Request', '', '', '192.168.1.5');
INSERT INTO radacct (radacctid, acctsessionid, acctuniqueid, username, groupname, realm, nasipaddress, nasportid, nasporttype, acctstarttime, acctupdatetime, acctstoptime, acctinterval, acctsessiontime, acctauthentic, connectinfo_start, connectinfo_stop, acctinputoctets, acctoutputoctets, calledstationid, callingstationid, acctterminatecause, servicetype, framedprotocol, framedipaddress) VALUES (585, '58ac0c6f00000001', '5a0212f4345dc4feebf06cbd4644b053', 'a1', NULL, NULL, '192.168.1.1', '00000001', 'Wireless-802.11', '2017-02-21 13:17:02+03:30', '2017-02-21 13:17:14+03:30', '2017-02-21 13:17:14+03:30', NULL, 12, '', '', '', 0, 0, '0A-00-27-00-00-00', '08-00-27-C2-EB-95', 'User-Request', '', '', '192.168.1.5');
INSERT INTO radacct (radacctid, acctsessionid, acctuniqueid, username, groupname, realm, nasipaddress, nasportid, nasporttype, acctstarttime, acctupdatetime, acctstoptime, acctinterval, acctsessiontime, acctauthentic, connectinfo_start, connectinfo_stop, acctinputoctets, acctoutputoctets, calledstationid, callingstationid, acctterminatecause, servicetype, framedprotocol, framedipaddress) VALUES (580, '58ac0aaa00000001', '8a29d7842d17c18d081a5086d8f07eef', 'a2', NULL, NULL, '192.168.1.1', '00000001', 'Wireless-802.11', '2017-02-21 13:09:23+03:30', '2017-02-21 13:11:16+03:30', '2017-02-21 13:11:16+03:30', NULL, 113, '', '', '', 353044, 99301, '0A-00-27-00-00-00', '08-00-27-C2-EB-95', 'User-Request', '', '', '192.168.1.5');
INSERT INTO radacct (radacctid, acctsessionid, acctuniqueid, username, groupname, realm, nasipaddress, nasportid, nasporttype, acctstarttime, acctupdatetime, acctstoptime, acctinterval, acctsessiontime, acctauthentic, connectinfo_start, connectinfo_stop, acctinputoctets, acctoutputoctets, calledstationid, callingstationid, acctterminatecause, servicetype, framedprotocol, framedipaddress) VALUES (584, '58ac0c6300000001', 'cd2d29fcb1c7ebfa0e9aa90f5877d948', 'a1', NULL, NULL, '192.168.1.1', '00000001', 'Wireless-802.11', '2017-02-21 13:16:22+03:30', '2017-02-21 13:16:23+03:30', '2017-02-21 13:16:23+03:30', NULL, 1, '', '', '', 0, 115, '0A-00-27-00-00-00', '08-00-27-C2-EB-95', 'User-Request', '', '', '192.168.1.5');


--
-- Name: radacct_radacctid_seq; Type: SEQUENCE SET; Schema: public; Owner: radius
--

SELECT pg_catalog.setval('radacct_radacctid_seq', 596, true);


--
-- Data for Name: radcheck; Type: TABLE DATA; Schema: public; Owner: radius
--

INSERT INTO radcheck (id, username, attribute, op, value) VALUES (999, 'a1', 'Cleartext-Password', ':=', '1');
INSERT INTO radcheck (id, username, attribute, op, value) VALUES (1000, 'a2', 'Cleartext-Password', ':=', '2');
INSERT INTO radcheck (id, username, attribute, op, value) VALUES (1001, 'a3', 'Cleartext-Password', ':=', '1');
INSERT INTO radcheck (id, username, attribute, op, value) VALUES (1002, 'a4', 'Cleartext-Password', ':=', '2');

--
-- Name: radcheck_id_seq; Type: SEQUENCE SET; Schema: public; Owner: radius
--

SELECT pg_catalog.setval('radcheck_id_seq', 853, true);


--
-- Data for Name: radgroupcheck; Type: TABLE DATA; Schema: public; Owner: radius
--

INSERT INTO radgroupcheck (id, groupname, attribute, op, value) VALUES (1, 'group1', 'Login-Time', ':=', 'Mo1000-1800');
INSERT INTO radgroupcheck (id, groupname, attribute, op, value) VALUES (2, 'group2', 'Login-Time', ':=', 'Mo1000-1800');
INSERT INTO radgroupcheck (id, groupname, attribute, op, value) VALUES (3, 'group3', 'Login-Time', ':=', 'Mo1000-1800');
INSERT INTO radgroupcheck (id, groupname, attribute, op, value) VALUES (4, 'group4', 'Login-Time', ':=', 'Mo1000-1800');

--
-- Name: radgroupcheck_id_seq; Type: SEQUENCE SET; Schema: public; Owner: radius
--

SELECT pg_catalog.setval('radgroupcheck_id_seq', 559, true);


--
-- Data for Name: radgroupdomainpolicy; Type: TABLE DATA; Schema: public; Owner: radius
--



--
-- Name: radgroupdomainpolicy_id_seq; Type: SEQUENCE SET; Schema: public; Owner: radius
--

SELECT pg_catalog.setval('radgroupdomainpolicy_id_seq', 1, false);


--
-- Data for Name: radgroupmimetypepolicy; Type: TABLE DATA; Schema: public; Owner: radius
--



--
-- Name: radgroupmimetypepolicy_id_seq; Type: SEQUENCE SET; Schema: public; Owner: radius
--

SELECT pg_catalog.setval('radgroupmimetypepolicy_id_seq', 1, false);


--
-- Data for Name: radgroupreply; Type: TABLE DATA; Schema: public; Owner: radius
--



--
-- Name: radgroupreply_id_seq; Type: SEQUENCE SET; Schema: public; Owner: radius
--

SELECT pg_catalog.setval('radgroupreply_id_seq', 1, true);


--
-- Data for Name: radippool; Type: TABLE DATA; Schema: public; Owner: radius
--



--
-- Name: radippool_id_seq; Type: SEQUENCE SET; Schema: public; Owner: radius
--

SELECT pg_catalog.setval('radippool_id_seq', 1, false);


--
-- Data for Name: radpostauth; Type: TABLE DATA; Schema: public; Owner: radius
--



--
-- Name: radpostauth_id_seq; Type: SEQUENCE SET; Schema: public; Owner: radius
--

SELECT pg_catalog.setval('radpostauth_id_seq', 1305, true);


--
-- Data for Name: radreply; Type: TABLE DATA; Schema: public; Owner: radius
--



--
-- Name: radreply_id_seq; Type: SEQUENCE SET; Schema: public; Owner: radius
--

SELECT pg_catalog.setval('radreply_id_seq', 1, true);


--
-- Data for Name: radusergroup; Type: TABLE DATA; Schema: public; Owner: radius
--

INSERT INTO radusergroup (id, username, groupname, priority) VALUES (1, 'a1', 'group1', 1);


--
-- Name: radusergroup_id_seq; Type: SEQUENCE SET; Schema: public; Owner: radius
--

SELECT pg_catalog.setval('radusergroup_id_seq', 511, true);


--
-- Data for Name: tc_class_id; Type: TABLE DATA; Schema: public; Owner: radius
--



--
-- Name: tc_class_id_id_seq; Type: SEQUENCE SET; Schema: public; Owner: radius
--

SELECT pg_catalog.setval('tc_class_id_id_seq', 1, false);


--
-- Name: app_filter_pkey; Type: CONSTRAINT; Schema: public; Owner: radius
--

ALTER TABLE ONLY app_filter
    ADD CONSTRAINT app_filter_pkey PRIMARY KEY (id);


--
-- Name: mac_auth_pkey; Type: CONSTRAINT; Schema: public; Owner: radius
--

ALTER TABLE ONLY mac_auth
    ADD CONSTRAINT mac_auth_pkey PRIMARY KEY (mac);


--
-- Name: nas_pkey; Type: CONSTRAINT; Schema: public; Owner: radius
--

ALTER TABLE ONLY nas
    ADD CONSTRAINT nas_pkey PRIMARY KEY (id);


--
-- Name: policy_fw_policy_order_key; Type: CONSTRAINT; Schema: public; Owner: radius
--

ALTER TABLE ONLY policy_fw
    ADD CONSTRAINT policy_fw_policy_order_key UNIQUE (policy_order);


--
-- Name: qos_config_pkey; Type: CONSTRAINT; Schema: public; Owner: radius
--

ALTER TABLE ONLY qos_config
    ADD CONSTRAINT qos_config_pkey PRIMARY KEY (id);


--
-- Name: radacct_acctuniqueid_key; Type: CONSTRAINT; Schema: public; Owner: radius
--

ALTER TABLE ONLY radacct
    ADD CONSTRAINT radacct_acctuniqueid_key UNIQUE (acctuniqueid);


--
-- Name: radacct_pkey; Type: CONSTRAINT; Schema: public; Owner: radius
--

ALTER TABLE ONLY radacct
    ADD CONSTRAINT radacct_pkey PRIMARY KEY (radacctid);


--
-- Name: radcheck_pkey; Type: CONSTRAINT; Schema: public; Owner: radius
--

ALTER TABLE ONLY radcheck
    ADD CONSTRAINT radcheck_pkey PRIMARY KEY (id);


--
-- Name: radgroupcheck_pkey; Type: CONSTRAINT; Schema: public; Owner: radius
--

ALTER TABLE ONLY radgroupcheck
    ADD CONSTRAINT radgroupcheck_pkey PRIMARY KEY (id);


--
-- Name: radgroupreply_pkey; Type: CONSTRAINT; Schema: public; Owner: radius
--

ALTER TABLE ONLY radgroupreply
    ADD CONSTRAINT radgroupreply_pkey PRIMARY KEY (id);


--
-- Name: radpostauth_pkey; Type: CONSTRAINT; Schema: public; Owner: radius
--

ALTER TABLE ONLY radpostauth
    ADD CONSTRAINT radpostauth_pkey PRIMARY KEY (id);


--
-- Name: radreply_pkey; Type: CONSTRAINT; Schema: public; Owner: radius
--

ALTER TABLE ONLY radreply
    ADD CONSTRAINT radreply_pkey PRIMARY KEY (id);


--
-- Name: radusergroup_pkey; Type: CONSTRAINT; Schema: public; Owner: radius
--

ALTER TABLE ONLY radusergroup
    ADD CONSTRAINT radusergroup_pkey PRIMARY KEY (id);


--
-- Name: nas_nasname; Type: INDEX; Schema: public; Owner: radius
--

CREATE INDEX nas_nasname ON nas USING btree (nasname);


--
-- Name: policy_fw_id; Type: INDEX; Schema: public; Owner: radius
--

CREATE UNIQUE INDEX policy_fw_id ON policy_fw USING btree (policy_id);


--
-- Name: radacct_active_session_idx; Type: INDEX; Schema: public; Owner: radius
--

CREATE INDEX radacct_active_session_idx ON radacct USING btree (acctuniqueid) WHERE (acctstoptime IS NULL);


--
-- Name: radacct_bulk_close; Type: INDEX; Schema: public; Owner: radius
--

CREATE INDEX radacct_bulk_close ON radacct USING btree (nasipaddress, acctstarttime) WHERE (acctstoptime IS NULL);


--
-- Name: radacct_start_user_idx; Type: INDEX; Schema: public; Owner: radius
--

CREATE INDEX radacct_start_user_idx ON radacct USING btree (acctstarttime, username);


--
-- Name: radcheck_username; Type: INDEX; Schema: public; Owner: radius
--

CREATE INDEX radcheck_username ON radcheck USING btree (username, attribute);


--
-- Name: radgroupcheck_groupname; Type: INDEX; Schema: public; Owner: radius
--

CREATE INDEX radgroupcheck_groupname ON radgroupcheck USING btree (groupname, attribute);


--
-- Name: radgroupreply_groupname; Type: INDEX; Schema: public; Owner: radius
--

CREATE INDEX radgroupreply_groupname ON radgroupreply USING btree (groupname, attribute);


--
-- Name: radreply_username; Type: INDEX; Schema: public; Owner: radius
--

CREATE INDEX radreply_username ON radreply USING btree (username, attribute);


--
-- Name: radusergroup_username; Type: INDEX; Schema: public; Owner: radius
--

CREATE INDEX radusergroup_username ON radusergroup USING btree (username);


--
-- Name: public; Type: ACL; Schema: -; Owner: postgres
--

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM postgres;
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO PUBLIC;


--
-- PostgreSQL database dump complete
--

