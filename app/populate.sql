TRUNCATE public."user", public.device_type, public.device, public.user_device, public.action CASCADE;

INSERT INTO public."user" (id, name, email, access_token, access_token_update) VALUES (1, 'MartinHeinz', 'martin7.heinz@gmail.com', '5c36ab84439c45a3719644c0d9bd7b31929afd9f', '2018-12-24 10:23:54');
INSERT INTO public."user" (id, name, email, access_token, access_token_update) VALUES (2, 'TestUser', 'testuser@domain.com', '5c36ab84439c55a3c196f4csd9bd7b319291239f', '2018-12-10 15:12:34');

INSERT INTO public.device_type (id, type_id, description, user_id, correctness_hash) VALUES (23525, '12ef8ea3-ba06-4aa9-904e-d5a9f35b09c5', 'raspberry', 1, '$2b$12$xLtcgV/Bqt4vfJfgnI1Hiewk90XJNYyAzgGKEV4P21/GJsUDGf6HC');
INSERT INTO public.device_type (id, type_id, description, user_id, correctness_hash) VALUES (12452, 'dbb028df-87e7-452d-b160-19e03d93f239', 'ESP32', 1, '$2b$12$8W3683MfW6xkhg1hNAQKTOOaUWgWibuYQpMgOlpu0M98HXIukNea6');

INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi, correctness_hash) VALUES (23, false, 23525, 1, 'my_raspberry', '$2b$12$1xxxxxxxxxxxxxxxxxxxxuZLbwxnpY0o58unSvIPxddLxGystU.Mq', '$2b$12$h15DOn5o9Lwb/dsgJMhSqew6s1skMN9PyLEGauBhZ6.DHiM4j88aW');
INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi, correctness_hash) VALUES (45, false, 23525, 2, 'my_raspberry', '$2b$12$2xxxxxxxxxxxxxxxxxxxxuUvk5iqq7yxVSBXWMofTBLgEj3jXioHu', '$2b$12$RRwdlQYjOENpiybTRiV4gOFc5reJ5W./azx4esMa3ufGepaTdZ7v.');
INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi, correctness_hash) VALUES (34, false, 12452, 2, 'my_ESP32', '$2b$12$2xxxxxxxxxxxxxxxxxxxxu9vIxS.wvIOPeYz88BA5e/t3FlezwvUm', '$2b$12$Qe6FlmfxZpF6HfdYmXyH9u65GSZVW9MKYrNY/PDRbdTa0r6ga1N1G');
INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi, correctness_hash) VALUES (37, false, 12452, 2, 'my_ESP32', '$2b$12$2xxxxxxxxxxxxxxxxxxxxu9vIxS.wvIOPeYz88BA5e/t3FlezwvUm', '$2b$12$KtQAaHuZilnddnnVaGEQ6utajeSH82UhxE6plZoScslZg6AkN.Lxq');

INSERT INTO public.action (id, name, device_id, correctness_hash) VALUES (1, 'On', 23, '$2b$12$Dq5rUbOpaWB5Chy/smeq0e30me/rphDF5SxMa1cp4AdyzXiy/sx6.');
INSERT INTO public.action (id, name, device_id, correctness_hash) VALUES (2, 'Off', 23, '$2b$12$tChAsiaC0qrWQDOxlZhasuOZ/uQgmaDHY7hekx22n9sq9Q6YhKn2m');
INSERT INTO public.action (id, name, device_id, correctness_hash) VALUES (3, 'Stat', 45, '$2b$12$AplltumV4pkiUG1JhC/VBO8FW/F3nChSStBBroKuI30nDsWWFnptG');
INSERT INTO public.action (id, name, device_id, correctness_hash) VALUES (4, 'Beep', 45, '$2b$12$UGUPgFQIZvBxMCnjQsv7Ye5VK2K8r5x70I0nVAzw16yGOFfWbwVbG');
INSERT INTO public.action (id, name, device_id, correctness_hash) VALUES (5, 'Temp', 34, '$2b$12$UsbxAJISMqya2VPEcecdGuQLSRL604qHs8cTU1Nlh5Yt1ckiKH7pG');
INSERT INTO public.action (id, name, device_id, correctness_hash) VALUES (6, 'Temp', 37, '$2b$12$SxaRTay152uvVfheKeyk1OXbfrjQBs7Xu3utqRlj1dRfJbDIftLSK');

INSERT INTO public.device_data (id, added, num_data, data, device_id, correctness_hash) VALUES (6, '2001-03-28 00:00:00+00', 66988873, '\x5c303031', 23, '$2b$12$RXHQ1j0e8iE2TSIT4LpdiOCM5xz4SUaxKJm88b2AA8s/4q3B73CLu'); -- 1000
INSERT INTO public.device_data (id, added, num_data, data, device_id, correctness_hash) VALUES (8, '2003-02-13 00:00:00+00', 129952183, '\x5c303031', 23, '$2b$12$0n4FFIXYJEpPmcS3IRCGn.CYSOFgPIJKZWxRNXZDDaLsLeVuXfA.G'); -- 2000
INSERT INTO public.device_data (id, added, num_data, data, device_id, correctness_hash) VALUES (4, '2004-05-14 00:00:00+00', 286346815, '\x5c303031', 23, '$2b$12$794bxOyPKfV3K7g1Mn1VTOMevZ9tlhZZcIysjqj6GN/al9IAXAmmm'); -- 4341
INSERT INTO public.device_data (id, added, num_data, data, device_id, correctness_hash) VALUES (12, '2012-09-11 00:00:00+00', 195426401, '\x5c303031', 23, '$2b$12$hrgQ6UUF4Y75Lo2Gyb.Eh.wYo.XMBL76A0dLRWL44x8WIJCW0HPfe'); -- 3000
INSERT INTO public.device_data (id, added, num_data, data, device_id, correctness_hash) VALUES (24, '2018-11-14 00:00:00+00', 32808983, '\x5c303031', 45, '$2b$12$UGcKsKwj7y1T6uaU94/p8u7wDmx7INX9Adp7.n2y5qTm81FCDPXxe'); -- 500
INSERT INTO public.device_data (id, added, num_data, data, device_id, correctness_hash) VALUES (25, '2018-12-11 00:00:00+00', 214357163, '\x5c303031', 45, '$2b$12$ug4.rQscibshf4LY.g1ZseSaG3TSABHZgS6oVkN7Iu4ZzZiDIDQFC'); -- 3245

INSERT INTO public.user_device (user_id, device_id) VALUES (2, 45);
INSERT INTO public.user_device (user_id, device_id) VALUES (2, 34);
INSERT INTO public.user_device (user_id, device_id) VALUES (2, 37);
INSERT INTO public.user_device (user_id, device_id) VALUES (1, 23);

SELECT pg_catalog.setval('public.action_id_seq', 6, true);
SELECT pg_catalog.setval('public.device_data_id_seq', 1, false);
SELECT pg_catalog.setval('public.device_id_seq', 1, false);
SELECT pg_catalog.setval('public.device_type_id_seq', 1, false);
SELECT pg_catalog.setval('public.scene_id_seq', 1, false);
SELECT pg_catalog.setval('public.user_id_seq', 2, true);



-- To dump insert statements from database:
-- (You need to be in directory from which you started DB with `docker-compose up`, e.g. `/postgres`)
-- docker exec -it $(docker-compose ps -q ) pg_dump -U<user> --column-inserts --data-only <db_name> > backup.sql
-- docker exec -it $(docker-compose ps -q ) pg_dump -Upostgres --column-inserts --data-only postgres > backup.sql