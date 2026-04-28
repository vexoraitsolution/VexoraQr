--
-- PostgreSQL database dump
--

\restrict eMMSCGUIKHGqtaXFqLdYUCms8DbuyLveehAvye73jQsCnRIqN1woEmhfBgje6he

-- Dumped from database version 18.1
-- Dumped by pg_dump version 18.1

-- Started on 2026-04-28 18:14:24

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- TOC entry 223 (class 1259 OID 94991)
-- Name: dynamic_qrs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.dynamic_qrs (
    short_code text NOT NULL,
    content_type text NOT NULL,
    content_data text NOT NULL,
    title text DEFAULT ''::text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    scan_count integer DEFAULT 0 NOT NULL,
    updated_at timestamp without time zone,
    expiry_date timestamp without time zone,
    last_scanned_at timestamp without time zone,
    time_based_content text,
    created_by_user text DEFAULT ''::text,
    server_settings text DEFAULT '{}'::text NOT NULL
);


ALTER TABLE public.dynamic_qrs OWNER TO postgres;

--
-- TOC entry 225 (class 1259 OID 96458)
-- Name: license_renewals; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.license_renewals (
    id integer NOT NULL,
    license_key character varying(255) NOT NULL,
    renewed_by character varying(255),
    old_expiry_date timestamp without time zone,
    new_expiry_date timestamp without time zone,
    renewed_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.license_renewals OWNER TO postgres;

--
-- TOC entry 224 (class 1259 OID 96457)
-- Name: license_renewals_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.license_renewals_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.license_renewals_id_seq OWNER TO postgres;

--
-- TOC entry 5061 (class 0 OID 0)
-- Dependencies: 224
-- Name: license_renewals_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.license_renewals_id_seq OWNED BY public.license_renewals.id;


--
-- TOC entry 220 (class 1259 OID 94954)
-- Name: licenses; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.licenses (
    id integer NOT NULL,
    license_key character varying(255) NOT NULL,
    is_active boolean DEFAULT true,
    expiry_date timestamp without time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    max_devices integer DEFAULT 1,
    devices text,
    note text DEFAULT ''::text,
    plan_id integer,
    features jsonb DEFAULT '{}'::jsonb NOT NULL,
    qr_scan_count integer DEFAULT 0 NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    duration integer
);


ALTER TABLE public.licenses OWNER TO postgres;

--
-- TOC entry 219 (class 1259 OID 94953)
-- Name: licenses_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.licenses_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.licenses_id_seq OWNER TO postgres;

--
-- TOC entry 5062 (class 0 OID 0)
-- Dependencies: 219
-- Name: licenses_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.licenses_id_seq OWNED BY public.licenses.id;


--
-- TOC entry 222 (class 1259 OID 94972)
-- Name: plans; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.plans (
    id integer NOT NULL,
    name text NOT NULL,
    features jsonb DEFAULT '{}'::jsonb NOT NULL
);


ALTER TABLE public.plans OWNER TO postgres;

--
-- TOC entry 221 (class 1259 OID 94971)
-- Name: plans_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.plans_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.plans_id_seq OWNER TO postgres;

--
-- TOC entry 5063 (class 0 OID 0)
-- Dependencies: 221
-- Name: plans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.plans_id_seq OWNED BY public.plans.id;


--
-- TOC entry 4885 (class 2604 OID 96461)
-- Name: license_renewals id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.license_renewals ALTER COLUMN id SET DEFAULT nextval('public.license_renewals_id_seq'::regclass);


--
-- TOC entry 4870 (class 2604 OID 94957)
-- Name: licenses id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.licenses ALTER COLUMN id SET DEFAULT nextval('public.licenses_id_seq'::regclass);


--
-- TOC entry 4878 (class 2604 OID 94975)
-- Name: plans id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.plans ALTER COLUMN id SET DEFAULT nextval('public.plans_id_seq'::regclass);


--
-- TOC entry 5053 (class 0 OID 94991)
-- Dependencies: 223
-- Data for Name: dynamic_qrs; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.dynamic_qrs (short_code, content_type, content_data, title, created_at, scan_count, updated_at, expiry_date, last_scanned_at, time_based_content, created_by_user, server_settings) FROM stdin;
5a462861	url	http://127.0.0.1:8000/	http://127.0.0.1:8000/	2026-04-03 17:33:28.137736	0	2026-04-03 17:48:11.321655	\N	\N	\N	950756BF-4491-47C8-B481-FF478D3644E2	{}
2225b8c4	url	https://chat.deepseek.com/a/chat/s/996083ca-9d17-4314-8dac-d9c628bbfd14	https://chat.deepseek.com/a/chat/s/996083ca-9d17-4314-8dac-d9c628bbfd14	2026-04-06 16:04:50.454413	2	2026-04-06 16:05:07.738312	2026-04-14 10:34:00	2026-04-06 16:05:35.183444	\N	B713F184-4B1B-495D-828F-108D78B99AB8	{}
257d8d09	url	https://facebook.com/	https://facebook.com/	2026-04-06 16:08:16.362825	0	\N	\N	\N	\N	B713F184-4B1B-495D-828F-108D78B99AB8	{}
79f7e337	url	https://facebook.com/	https://facebook.com/	2026-04-06 16:07:34.288854	2	2026-04-06 16:09:27.755226	\N	2026-04-06 16:09:45.737924	\N	B713F184-4B1B-495D-828F-108D78B99AB8	{"password_hash": "5380db90305a93fa3ec8cf0a0665bb3c99b47fbb71bd8f94bb01e8bb0e9f8bbc"}
3710d7e9	text	12	12	2026-04-08 18:12:43.828005	0	\N	\N	\N	\N	B713F184-4B1B-495D-828F-108D78B99AB8	{}
6c9dbdad	url	546546512	123	2026-04-03 12:41:05.941947	2	\N	\N	\N	\N	950756BF-4491-47C8-B481-FF478D3644E2	{}
b71cd8d6	text	kAwada	kAwada	2026-04-09 07:09:21.605783	3	2026-04-09 07:17:35.734805	\N	2026-04-09 12:37:22.866775	\N	B713F184-4B1B-495D-828F-108D78B99AB8	{}
bc53989f	text	test 1	32142	2026-04-09 19:18:32.927041	0	\N	\N	\N	\N	A2DA7FD6-233C-42DD-9042-C48232120004	{}
80bd2514	url	https://www.facebook.com/reel/1511839560289350	https://www.facebook.com/reel/1511839560289350	2026-04-27 23:53:48.638342	0	2026-04-27 23:54:52.295151	\N	\N	[{"days": ["mon"], "start": "23:54", "end": "23:55", "content_type": "url", "content_data": "", "title": "", "mapping_key": "test"}]	A2DA7FD6-233C-42DD-9042-C48232120004	{"content_mapping": {"test": {"content_type": "text", "content_data": "test", "title": "1213"}}, "active_mapping_key": "test"}
7a31e65e	text	mk bro	mk bro	2026-04-03 14:41:56.104985	11	2026-04-03 14:52:23.602466	2026-04-03 16:20:00	2026-04-03 15:44:28.738397	\N	950756BF-4491-47C8-B481-FF478D3644E2	{"scan_limit": 10, "password_hash": "858ab72399ad39a7b5389fbf6f10bd55410b2edfba50185db2422af705a84f07"}
\.


--
-- TOC entry 5055 (class 0 OID 96458)
-- Dependencies: 225
-- Data for Name: license_renewals; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.license_renewals (id, license_key, renewed_by, old_expiry_date, new_expiry_date, renewed_at) FROM stdin;
\.


--
-- TOC entry 5050 (class 0 OID 94954)
-- Dependencies: 220
-- Data for Name: licenses; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.licenses (id, license_key, is_active, expiry_date, created_at, max_devices, devices, note, plan_id, features, qr_scan_count, updated_at, duration) FROM stdin;
15	E05BDF72-7A67-4518-AC0D-DE225CE2EF00	t	2026-04-16 18:46:20.930986	2026-04-09 08:46:49.759175+05:30	1	["6b4072a83439932e684b39d3954f64af4d4ca4d2340148827d1a240226385b3f"]	12	1	{}	0	2026-04-09 10:03:31.347468	7
16	FBEF9723-CF24-4CA7-899D-63EFF5FD1FD0	t	2026-04-16 18:46:33.565873	2026-04-09 08:56:30.83078+05:30	1	["6b4072a83439932e684b39d3954f64af4d4ca4d2340148827d1a240226385b3f"]	12	1	{"max_scans": 12}	0	2026-04-09 08:59:53.359044	7
17	A2DA7FD6-233C-42DD-9042-C48232120004	t	2027-04-09 19:17:34.315525	2026-04-09 19:17:34.315688+05:30	1	["6b4072a83439932e684b39d3954f64af4d4ca4d2340148827d1a240226385b3f"]	ishan Sir	1	{}	0	2026-04-09 19:17:34.315688	365
\.


--
-- TOC entry 5052 (class 0 OID 94972)
-- Dependencies: 222
-- Data for Name: plans; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.plans (id, name, features) FROM stdin;
1	pro	{"analytics": true, "customize": true, "max_scans": 10, "time_based": true, "custom_logo": true, "dynamic_qrs": true}
3	leg	{"analytics": false, "customize": false, "max_scans": 10, "time_based": false, "custom_logo": false, "dynamic_qrs": false}
\.


--
-- TOC entry 5064 (class 0 OID 0)
-- Dependencies: 224
-- Name: license_renewals_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.license_renewals_id_seq', 1, false);


--
-- TOC entry 5065 (class 0 OID 0)
-- Dependencies: 219
-- Name: licenses_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.licenses_id_seq', 17, true);


--
-- TOC entry 5066 (class 0 OID 0)
-- Dependencies: 221
-- Name: plans_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.plans_id_seq', 3, true);


--
-- TOC entry 4897 (class 2606 OID 95003)
-- Name: dynamic_qrs dynamic_qrs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.dynamic_qrs
    ADD CONSTRAINT dynamic_qrs_pkey PRIMARY KEY (short_code);


--
-- TOC entry 4900 (class 2606 OID 96468)
-- Name: license_renewals license_renewals_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.license_renewals
    ADD CONSTRAINT license_renewals_pkey PRIMARY KEY (id);


--
-- TOC entry 4889 (class 2606 OID 94967)
-- Name: licenses licenses_license_key_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.licenses
    ADD CONSTRAINT licenses_license_key_key UNIQUE (license_key);


--
-- TOC entry 4891 (class 2606 OID 94965)
-- Name: licenses licenses_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.licenses
    ADD CONSTRAINT licenses_pkey PRIMARY KEY (id);


--
-- TOC entry 4893 (class 2606 OID 94985)
-- Name: plans plans_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.plans
    ADD CONSTRAINT plans_name_key UNIQUE (name);


--
-- TOC entry 4895 (class 2606 OID 94983)
-- Name: plans plans_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.plans
    ADD CONSTRAINT plans_pkey PRIMARY KEY (id);


--
-- TOC entry 4898 (class 1259 OID 95018)
-- Name: idx_dynamic_qrs_owner; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_dynamic_qrs_owner ON public.dynamic_qrs USING btree (created_by_user);


--
-- TOC entry 4887 (class 1259 OID 94970)
-- Name: idx_licenses_key; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_licenses_key ON public.licenses USING btree (license_key);


--
-- TOC entry 4901 (class 2606 OID 94986)
-- Name: licenses licenses_plan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.licenses
    ADD CONSTRAINT licenses_plan_id_fkey FOREIGN KEY (plan_id) REFERENCES public.plans(id) ON DELETE SET NULL;


-- Completed on 2026-04-28 18:14:24

--
-- PostgreSQL database dump complete
--

\unrestrict eMMSCGUIKHGqtaXFqLdYUCms8DbuyLveehAvye73jQsCnRIqN1woEmhfBgje6he

