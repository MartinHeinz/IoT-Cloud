TRUNCATE public."user", public.device_type, public.device, public.user_device CASCADE;

INSERT INTO public."user" (id, name, email, access_token, access_token_update) VALUES (1, 'MartinHeinz', 'martin7.heinz@gmail.com', '5c36ab84439c45a3719644c0d9bd7b31929afd9f', '2018-12-24 10:23:54');
INSERT INTO public."user" (id, name, email, access_token, access_token_update) VALUES (2, 'TestUser', 'testuser@domain.com', '5c36ab84439c55a3c196f4csd9bd7b319291239f', '2018-12-10 15:12:34');

INSERT INTO public.device_type (id, type_id, description, user_id) VALUES (23525, '12ef8ea3-ba06-4aa9-904e-d5a9f35b09c5', 'raspberry', 1);
INSERT INTO public.device_type (id, type_id, description, user_id) VALUES (12452, 'dbb028df-87e7-452d-b160-19e03d93f239', 'ESP32', 1);

INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi) VALUES (23, false, 23525, 1, 'my_raspberry', '$2b$12$1xxxxxxxxxxxxxxxxxxxxuZLbwxnpY0o58unSvIPxddLxGystU.Mq');
INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi) VALUES (45, false, 23525, 2, 'my_raspberry', '$2b$12$2xxxxxxxxxxxxxxxxxxxxuUvk5iqq7yxVSBXWMofTBLgEj3jXioHu');
INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi) VALUES (34, false, 12452, 2, 'my_ESP32', '$2b$12$2xxxxxxxxxxxxxxxxxxxxu9vIxS.wvIOPeYz88BA5e/t3FlezwvUm');
INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi) VALUES (37, false, 12452, 2, 'my_ESP32', '$2b$12$2xxxxxxxxxxxxxxxxxxxxu9vIxS.wvIOPeYz88BA5e/t3FlezwvUm');

INSERT INTO public.action (id, name, device_id) VALUES (1, 'On', 23);
INSERT INTO public.action (id, name, device_id) VALUES (2, 'Off', 23);
INSERT INTO public.action (id, name, device_id) VALUES (3, 'Stat', 45);
INSERT INTO public.action (id, name, device_id) VALUES (4, 'Beep', 45);
INSERT INTO public.action (id, name, device_id) VALUES (5, 'Temp', 34);
INSERT INTO public.action (id, name, device_id) VALUES (6, 'Temp', 37);

INSERT INTO public.device_data (id, added, num_data, data, device_id) VALUES (6, '2001-03-28 00:00:00+00', 66988873, '\x5c303031', 23); -- 1000
INSERT INTO public.device_data (id, added, num_data, data, device_id) VALUES (8, '2003-02-13 00:00:00+00', 129952183, '\x5c303031', 23); -- 2000
INSERT INTO public.device_data (id, added, num_data, data, device_id) VALUES (4, '2004-05-14 00:00:00+00', 286346815, '\x5c303031', 23); -- 4341
INSERT INTO public.device_data (id, added, num_data, data, device_id) VALUES (12, '2012-09-11 00:00:00+00', 195426401, '\x5c303031', 23); -- 3000
INSERT INTO public.device_data (id, added, num_data, data, device_id) VALUES (24, '2018-11-14 00:00:00+00', 32808983, '\x5c303031', 45); -- 500
INSERT INTO public.device_data (id, added, num_data, data, device_id) VALUES (25, '2018-12-11 00:00:00+00', 214357163, '\x5c303031', 45); -- 3245

INSERT INTO public.user_device (user_id, device_id) VALUES (2, 45);
INSERT INTO public.user_device (user_id, device_id) VALUES (1, 23);
INSERT INTO public.user_device (user_id, device_id) VALUES (2, 37);
INSERT INTO public.user_device (user_id, device_id) VALUES (2, 34);

SELECT pg_catalog.setval('public.action_id_seq', 6, true);
SELECT pg_catalog.setval('public.device_data_id_seq', 1, false);
SELECT pg_catalog.setval('public.device_id_seq', 1, false);
SELECT pg_catalog.setval('public.device_type_id_seq', 1, false);
SELECT pg_catalog.setval('public.scene_id_seq', 1, false);
SELECT pg_catalog.setval('public.user_id_seq', 2, true);



-- To dump insert statements from database:
-- pg_dump -h <host> -U <user> --column-inserts --data-only <db>
-- pg_dump -h localhost -U postgres --column-inserts --data-only flask_test