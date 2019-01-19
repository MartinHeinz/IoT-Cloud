TRUNCATE public."user", public.device_type, public.device, public.user_device, public.action CASCADE;

INSERT INTO public."user" (id, name, email, access_token, access_token_update) VALUES (1, 'MartinHeinz', 'martin7.heinz@gmail.com', '5c36ab84439c45a3719644c0d9bd7b31929afd9f', '2018-12-24 10:23:54');
INSERT INTO public."user" (id, name, email, access_token, access_token_update) VALUES (2, 'TestUser', 'testuser@domain.com', '5c36ab84439c55a3c196f4csd9bd7b319291239f', '2018-12-10 15:12:34');

INSERT INTO public.device_type (id, type_id, description, user_id, correctness_hash) VALUES (23525, '12ef8ea3-ba06-4aa9-904e-d5a9f35b09c5', 'raspberry', 1, '$2b$12$xLtcgV/Bqt4vfJfgnI1Hiewk90XJNYyAzgGKEV4P21/GJsUDGf6HC');
INSERT INTO public.device_type (id, type_id, description, user_id, correctness_hash) VALUES (12452, 'dbb028df-87e7-452d-b160-19e03d93f239', 'ESP32', 1, '$2b$12$8W3683MfW6xkhg1hNAQKTOOaUWgWibuYQpMgOlpu0M98HXIukNea6');

INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi, correctness_hash) VALUES (23, '0', 23525, 1, 'my_raspberry', '$2b$12$1xxxxxxxxxxxxxxxxxxxxuZLbwxnpY0o58unSvIPxddLxGystU.Mq', '$2b$12$h15DOn5o9Lwb/dsgJMhSqew6s1skMN9PyLEGauBhZ6.DHiM4j88aW');
INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi, correctness_hash) VALUES (45, '0', 23525, 2, 'my_raspberry', '$2b$12$2xxxxxxxxxxxxxxxxxxxxuUvk5iqq7yxVSBXWMofTBLgEj3jXioHu', '$2b$12$RRwdlQYjOENpiybTRiV4gOFc5reJ5W./azx4esMa3ufGepaTdZ7v.');
INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi, correctness_hash) VALUES (34, '0', 12452, 2, 'my_ESP32', '$2b$12$2xxxxxxxxxxxxxxxxxxxxu9vIxS.wvIOPeYz88BA5e/t3FlezwvUm', '$2b$12$Qe6FlmfxZpF6HfdYmXyH9u65GSZVW9MKYrNY/PDRbdTa0r6ga1N1G');
INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi, correctness_hash) VALUES (37, '0', 12452, 2, 'my_ESP32', '$2b$12$2xxxxxxxxxxxxxxxxxxxxu9vIxS.wvIOPeYz88BA5e/t3FlezwvUm', '$2b$12$KtQAaHuZilnddnnVaGEQ6utajeSH82UhxE6plZoScslZg6AkN.Lxq');

INSERT INTO public.action (id, name, device_id, correctness_hash) VALUES (1, 'On', 23, '$2b$12$Dq5rUbOpaWB5Chy/smeq0e30me/rphDF5SxMa1cp4AdyzXiy/sx6.');
INSERT INTO public.action (id, name, device_id, correctness_hash) VALUES (2, 'Off', 23, '$2b$12$tChAsiaC0qrWQDOxlZhasuOZ/uQgmaDHY7hekx22n9sq9Q6YhKn2m');
INSERT INTO public.action (id, name, device_id, correctness_hash) VALUES (3, 'Stat', 45, '$2b$12$AplltumV4pkiUG1JhC/VBO8FW/F3nChSStBBroKuI30nDsWWFnptG');
INSERT INTO public.action (id, name, device_id, correctness_hash) VALUES (4, 'Beep', 45, '$2b$12$UGUPgFQIZvBxMCnjQsv7Ye5VK2K8r5x70I0nVAzw16yGOFfWbwVbG');
INSERT INTO public.action (id, name, device_id, correctness_hash) VALUES (5, 'Temp', 34, '$2b$12$UsbxAJISMqya2VPEcecdGuQLSRL604qHs8cTU1Nlh5Yt1ckiKH7pG');
INSERT INTO public.action (id, name, device_id, correctness_hash) VALUES (6, 'Temp', 37, '$2b$12$SxaRTay152uvVfheKeyk1OXbfrjQBs7Xu3utqRlj1dRfJbDIftLSK');

INSERT INTO public.device_data (id, added, num_data, data, device_id, correctness_hash) VALUES (6, 985734000, 66988873, '\x5c303031', 23, '$2b$12$9bSwB48OQnZ3Aby2MFFFDOaOGs8OKg3M22Bv0REyh5teKx3YldSTq'); -- '2001-03-28 00:00:00+00', 1000
INSERT INTO public.device_data (id, added, num_data, data, device_id, correctness_hash) VALUES (8, 1045090800, 129952183, '\x5c303031', 23, '$2b$12$EVlhvYDlqncIqhkqwd2Pi.V4EfPie/tT6ES9/CJDPowRDcmo7dAYe'); -- '2003-02-13 00:00:00+00', 2000
INSERT INTO public.device_data (id, added, num_data, data, device_id, correctness_hash) VALUES (4, 1084489200, 286346815, '\x5c303031', 23, '$2b$12$SdnF.bJFgHuDJs.k2whfL.6jqlZuChndN8z5g6foM6OM5HvYpVhMu'); -- '2004-05-14 00:00:00+00', 4341
INSERT INTO public.device_data (id, added, num_data, data, device_id, correctness_hash) VALUES (12, 1347318000, 195426401, '\x5c303031', 23, '$2b$12$Fa5woEi.uPVY3S86ND4O7umF.U3DLg1XEeQt/cze9fNMnkVfTiPga'); -- '2012-09-11 00:00:00+00', 3000
INSERT INTO public.device_data (id, added, num_data, data, device_id, correctness_hash) VALUES (24, 1542150000, 32808983, '\x5c303031', 45, '$2b$12$BF1pH6slN7n9y1qzl4KPQORjZxxKOCFEa5ThqS/Id7u3iZw3qjg76'); -- '2018-11-14 00:00:00+00',  500
INSERT INTO public.device_data (id, added, num_data, data, device_id, correctness_hash) VALUES (25, 1544482800, 214357163, '\x5c303031', 45, '$2b$12$fd1vKE/zQpJ8yyAhFJ.gPOu3YuEDtNtyfP1apcHf6ZaAu6oNoHpLm'); -- '2018-12-11 00:00:00+00', 3245

INSERT INTO public.user_device (user_id, device_id, device_public_session_key, added) VALUES (1, 23, NULL, NULL);
INSERT INTO public.user_device (user_id, device_id, device_public_session_key, added) VALUES (2, 45, NULL, NULL);
INSERT INTO public.user_device (user_id, device_id, device_public_session_key, added) VALUES (2, 34, NULL, NULL);
INSERT INTO public.user_device (user_id, device_id, device_public_session_key, added) VALUES (2, 37, NULL, NULL);

SELECT pg_catalog.setval('public.action_id_seq', 6, true);
SELECT pg_catalog.setval('public.device_data_id_seq', 1, false);
SELECT pg_catalog.setval('public.device_id_seq', 1, false);
SELECT pg_catalog.setval('public.device_type_id_seq', 1, false);
SELECT pg_catalog.setval('public.scene_id_seq', 1, false);
SELECT pg_catalog.setval('public.user_id_seq', 2, true);


-- public.device_data.added was converted as `int(time.mktime(parser.parse('2018-12-11 00:00:00+00').timetuple()))`

-- To dump insert statements from database:
-- (You need to be in directory from which you started DB with `docker-compose up`, e.g. `/postgres`)
-- docker exec -it $(docker-compose ps -q ) pg_dump -U<user> --column-inserts --data-only <db_name> > backup.sql
-- docker exec -it $(docker-compose ps -q ) pg_dump -Upostgres --column-inserts --data-only postgres > backup.sql