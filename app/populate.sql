TRUNCATE public.acl, public.action, public.device, public.device_data, public.device_type, public.mqtt_user, public.scene, public.scene_device, public."user", public.user_device CASCADE;

INSERT INTO public."user" (id, name, email, access_token, access_token_update) VALUES (1, 'MartinHeinz', 'martin7.heinz@gmail.com', '5c36ab84439c45a3719644c0d9bd7b31929afd9f', '2018-12-24 10:23:54');
INSERT INTO public."user" (id, name, email, access_token, access_token_update) VALUES (2, 'TestUser', 'testuser@domain.com', '5c36ab84439c55a3c196f4csd9bd7b319291239f', '2018-12-10 15:12:34');
INSERT INTO public."user" (id, name, email, access_token, access_token_update) VALUES (3, 'TestRunner', 'TestRunner@domain.com', '5c36ab84439c55a3c196f4csd9bd7b3d9291f39g', '2018-12-15 15:12:34');

INSERT INTO public.device_type (id, type_id, description, user_id, correctness_hash) VALUES (23525, '12ef8ea3-ba06-4aa9-904e-d5a9f35b09c5', '\x674141414141426356793147467255677779764b614d5939415f464f455666476d646e346974484b6d774a744e666d595157764c536f376e645a5a4e35756c4e5137504e4778575f656335524b5a376a45784a502d6151466a4c6539565938524b413d3d', 1, '$2b$12$4UaetPVYtRRSZhILDbBhLuivBgPlE6.Wz5nFXJqJdVHdySuscgKJO');
INSERT INTO public.device_type (id, type_id, description, user_id, correctness_hash) VALUES (12452, 'dbb028df-87e7-452d-b160-19e03d93f239', '\x67414141414142635679314779586b74416d7378613042496a334a3464774744315f3057357774614539726567794f37554e704f63307975434f5a4a526e755a796d5849697a676635477163426171583549345457675f41394c2d77337a366d47673d3d', 1, '$2b$12$Ya1AAz3OywUEryac0j7zLum6UPYTbaQ0WG0ggvRRgWjMQBdzjsWi6');

INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi, correctness_hash) VALUES (23, '\x30', 23525, 1, '\x674141414141426356793147526d634255314f78784771336742516d30693534646169514e55594562696b3449616269316a38754548677a44646b4364747873752d704251636d70587037656a6465416d79556947532d47567a55665370424b4b413d3d', '$2b$12$1xxxxxxxxxxxxxxxxxxxxuZLbwxnpY0o58unSvIPxddLxGystU.Mq', '$2b$12$9kK60Amt1Lf752xWfTXiIuGUR8Py0tSjlKGRt9W3FLyNy.zwvUf8y');
INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi, correctness_hash) VALUES (45, '\x30', 23525, 2, '\x67414141414142635679314868685251356d424a4575375a49342d4d446c526b4d376d457357545275684e4e5a3242586341347065796a75532d624c78335964376748523567437631765169676b66414272447172346767387976386f4e4b567a773d3d', '$2b$12$2xxxxxxxxxxxxxxxxxxxxuUvk5iqq7yxVSBXWMofTBLgEj3jXioHu', '$2b$12$UJgvb88Z1kM2CM33yGWrj.dSthfJGc2Y.duLhVIFqBcJ.0/1MGI82');
INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi, correctness_hash) VALUES (34, '\x30', 12452, 2, '\x67414141414142635679314870754d2d704d4274584732644c5137474b5579384d58516b4647537563553259374e716976324b43756243552d737246527570434366576c5762633971684161595638486f4e3667714f744a777737513173535974773d3d', '$2b$12$2xxxxxxxxxxxxxxxxxxxxu9vIxS.wvIOPeYz88BA5e/t3FlezwvUm', '$2b$12$IFyaLLUcX8t3uGnBCswu8eULWoegbLayx6s5MnVABW69am5FVRuri');
INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi, correctness_hash) VALUES (37, '\x30', 12452, 2, '\x674141414141426356793149546936495f61734d6271704634416173587236626d4a306b55435137686d564272455f3038652d5572676246476848494f543436613138304a464162714f2d385272594a793871324a575f42456b357a72444b356b413d3d', '$2b$12$2xxxxxxxxxxxxxxxxxxxxu9vIxS.wvIOPeYz88BA5e/t3FlezwvUm', '$2b$12$fGz2uC0cvPi1fTlcUU8Je.wE.hh7jZxRuk/xRlrsON5.WilfdoXEu');

INSERT INTO public.mqtt_user (id, username, password_hash, superuser, user_id, device_id) VALUES (1, 'device1', 'PBKDF2$sha256$10000$a0HFjEn8VZe04CxJ$Zd2UxhyYvlY5wIqycui58jCKVsNxL1MQ', 0, NULL, 23);  -- device1_pass
INSERT INTO public.mqtt_user (id, username, password_hash, superuser, user_id, device_id) VALUES (2, 'MartinHeinz', 'PBKDF2$sha256$10000$8dd35yJLqjFIpeMO$oQwtPcs4FhcZGihX71LtN6fm+yVWcb4v', 0, 1, NULL);  -- password1
INSERT INTO public.mqtt_user (id, username, password_hash, superuser, user_id, device_id) VALUES (3, 'device2', 'PBKDF2$sha256$10000$kOVrAa3VULOtlcxS$BP686anaevC7t2hwxCzfvo5UaxOp1+YA', 0, NULL, 45);  -- device2_pass
INSERT INTO public.mqtt_user (id, username, password_hash, superuser, user_id, device_id) VALUES (4, 'device3', 'PBKDF2$sha256$10000$+tYVrce5IvbOPREB$haW4Atpabx2giJEeDBwaMIvKf3KNNop0', 0, NULL, 34);  -- device3_pass
INSERT INTO public.mqtt_user (id, username, password_hash, superuser, user_id, device_id) VALUES (5, 'device4', 'PBKDF2$sha256$10000$1RDrXIISPQKSfLvh$HXv5bYEQe7NepGBLmdp6rOydxuETaWNb', 0, NULL, 37);  -- device4_pass
INSERT INTO public.mqtt_user (id, username, password_hash, superuser, user_id, device_id) VALUES (6, 'TestUser', 'PBKDF2$sha256$10000$NsPHhalfv7Asj8mw$jRzH8ZEMh0B5oKPo2vRhcwhvmk0UIPgC', 0, 2, NULL);  -- password2

-- FOR SERVER USER AND DEBUGGING
INSERT INTO public.mqtt_user (id, username, password_hash, superuser) VALUES (7, 'admin', 'PBKDF2$sha256$10000$J8N0E3qluPAwm8uN$n8jehANuh+6ddOtNmopG0Jem79LzV+X4', 1);  -- password
INSERT INTO public.mqtt_user (id, username, password_hash, superuser, user_id) VALUES (8, 'testuser', 'PBKDF2$sha256$10000$qu5hXEoBLNeKuzR7$koo7Ozny5dpZE8Vy8GZVi6kcMvWVPrs6', 0, 2);  -- testuser

INSERT INTO acl (id, mqtt_user_id, username, topic, acc) VALUES (17, 8, 'testuser', 'read', 1);
INSERT INTO acl (id, mqtt_user_id, username, topic, acc) VALUES (18, 8, 'testuser', 'write', 2);
INSERT INTO acl (id, mqtt_user_id, username, topic, acc) VALUES (19, 8, 'testuser', 'both', 3);

INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (1, 1, 'device1', 'u:1/d:23/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (2, 1, 'device1', 'd:23/u:1/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (3, 1, 'device1', 'd:23/server/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (4, 1, 'device1', 'server/d:23/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (5, 2, 'MartinHeinz', 'u:1/23/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (6, 2, 'MartinHeinz', 'd:23/u:1/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (7, 2, 'MartinHeinz', 'u:1/server/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (8, 2, 'MartinHeinz', 'server/u:1/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (9, 3, 'device2', 'u:2/d:45/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (10, 3, 'device2', 'd:45/u:2/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (11, 3, 'device2', 'd:45/server/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (12, 3, 'device2', 'server/d:45/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (13, 6, 'TestUser', 'u:2/d:45/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (14, 6, 'TestUser', 'd:45/u:2/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (15, 6, 'TestUser', 'u:2/server/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (16, 6, 'TestUser', 'server/u:2/+', 1);

INSERT INTO public.action (id, name, device_id, correctness_hash) VALUES (1, '\x6741414141414263567931494a6c344b506c76754e343634614a6b6b54376f6c713937746130714e31733330594b73486743334b476756626f314c4d72584e436a6658454c6d4739377131754b3979434c7455646c4c52766f392d4f674175364d413d3d', 23, '$2b$12$PC4KWELmJJDjyFwdJfyYF.IfALYWfu5nMRGBo.wUp8TMIQZKOixOC');
INSERT INTO public.action (id, name, device_id, correctness_hash) VALUES (2, '\x67414141414142635679314939685a6d73794d6d7041307678547a5046587144455337385f7566417948462d64364c6a676a65526735694b634673486c5a436a6c42656544794a78314b725672785948367642394669366c5030554d327870494e773d3d', 23, '$2b$12$V6UEFPM/kaatcDeHq7PIu.XZK2RSKBvp/TE84O069RZQHV.Lf02oq');
INSERT INTO public.action (id, name, device_id, correctness_hash) VALUES (3, '\x67414141414142635679314a6b6d304751735f745174347550624a7439546856542d34586f39426c316b35337634794f7436703469554d595655626f597a5745485867516a4a54574f5045315f534451494931765559504643654e747256765463513d3d', 45, '$2b$12$0c7Al2CcrcFYRIxmSc/QBuHXsUlETiSUl1BiSyp4paiPLHClusRjC');
INSERT INTO public.action (id, name, device_id, correctness_hash) VALUES (4, '\x67414141414142635679314a5458422d684d47512d383276495144645a553233704c546e6a6c57534d496b2d4e4f54613949414f6b52355f6e7855324e2d6a44497755734e32304747547066654a6c58646b484675693141583932356869665644673d3d', 45, '$2b$12$E30.OK3PnUriqIR.utRguOdKDt5go8wDGV99guqYi.julwT.eR0Qe');
INSERT INTO public.action (id, name, device_id, correctness_hash) VALUES (5, '\x67414141414142635679314a462d594d5836494e736a6d7a4f304b49696e3258536d443447676134576845746e6846726b73715f756b59625471365f64552d326d5366703661494d4d54327333424179686550396e62676a744656336c506a7a6a513d3d', 34, '$2b$12$4TfT0Q.rJ6n5TtP1drl3.uItgkTSv.YpBn46JxqEF2pGEJYOspcpK');
INSERT INTO public.action (id, name, device_id, correctness_hash) VALUES (6, '\x67414141414142635679314b7942445a545a6545794c66536235504861306b476e666b547176533264675575303969486a4f7555774c7336456a73747647344f674e613566527746614438506761616f6e733452377872302d64447178524e6357773d3d', 37, '$2b$12$hq9priTeC3bFb4laIptQhOSCOwcaRVrEZjJ/7QuCiBMgqNLG2bK.S');

INSERT INTO public.device_data (id, tid, added, num_data, data, device_id, tid_bi, correctness_hash) VALUES (6, '\x67414141414142635679314b505441586f41776f6356687950625165646e545831452d346d394d427575313547665879496a797558396776757a385063672d79354a527a436b715a3054594d5179504c4a61736b55615977574d7545317145624b513d3d', 2116580122, 464064, '\x67414141414142635679314b71734e48556c516848385f30793059364d75526338774170554a563341305f5070414b796a4c675345714d334456755f5f5f437361745a33337278526454516f5755446c6f573132317a332d687771323338777269673d3d', 23, '$2b$12$23xxxxxxxxxxxxxxxxxxxuN5X.DMkHilBYQSsUWodebAG.asbqKNa', '$2b$12$dlyZ.ys2FqLMuzFli4MjE.LG1yBz/S/S2DOLVW87D9ijr3wFuTo0S');
INSERT INTO public.device_data (id, tid, added, num_data, data, device_id, tid_bi, correctness_hash) VALUES (8, '\x67414141414142635679314b6b68324d2d55554b495939684d767063535144584269505f746e55675f315f7534335a38703677774573586e2d526e76696f496a544e734233545f575435664e706e6d764231397836724235674e43686954436c52673d3d', 2244039737, 466263, '\x67414141414142635679314b68525538496e4e31746e74726258764174324f2d42514a4438495a6f68614e6c742d546c45752d366e53506f7546546f5445647031544f2d4f576944533944396a3149416a6955714a6d76356b5f55496d35464d56413d3d', 23, '$2b$12$23xxxxxxxxxxxxxxxxxxxu.ZfhXcDxDatkjrxC5f7I1S9D0G9uMI.', '$2b$12$tc/RZguU8touXJYtYW2Rl.xDc1RZynCgatDXlxixCuAmfe6mBQGpW');
INSERT INTO public.device_data (id, tid, added, num_data, data, device_id, tid_bi, correctness_hash) VALUES (4, '\x67414141414142635679314b463070347669525035464957706349633955656b52676d7a4539625a38476e365759664d6f71776e6143632d35624a7846463944733250624b2d6f414d556a514a4c4833324255435f4750556f7236794e2d493765413d3d', 2328646538, 471232, '\x67414141414142635679314b356a334d75446746784d4e375f31394f4567535664567a7a396661657a68465f69307159375533684b65382d3243416847374b3152475476644c61767558734a3567593136627a7930326f7661725f305a496f5149413d3d', 23, '$2b$12$23xxxxxxxxxxxxxxxxxxxuSfVK9H/a.JO/whZHvsU1Q39d26XzS/6', '$2b$12$ITJ4PaqU0yhVQc5Vdr53be9OuHo1THnvLzba2flTiGtbuW614K.NS');
INSERT INTO public.device_data (id, tid, added, num_data, data, device_id, tid_bi, correctness_hash) VALUES (12, '\x67414141414142635679314b4932514b4b45746c586e662d30394f4d63486d6c53356d6b4a4c655754536536746356624d54732d49517847354142686156433958305a416f3072666d794276754c7977626b6a4e585a42687669524e795243664f773d3d', 2893054513, 468360, '\x67414141414142635679314b5f574c5f714c435a6f707532395f784353347065353379507358307242656a693857546f556d426a71623439495a726474654153364e39574a424a48795a53437a65773654564b506157465f313030514a37464630413d3d', 23, '$2b$12$23xxxxxxxxxxxxxxxxxxxupooniyevX3UXhzktSF2tYwePP7PnQ6C', '$2b$12$9hUL8wo6yvhh2zUsMnDM4.USS4Wzgz/XjmT6LuQW7VHMUdNkQh4Ca');
INSERT INTO public.device_data (id, tid, added, num_data, data, device_id, tid_bi, correctness_hash) VALUES (24, '\x67414141414142635679314b553844324e374c3074504c5f464143725972577a4d436157366338452d57454e53785777737761696b6a6a444e65585a43437661587a79644d7759475a57795a437278486242673531442d476d7674322d4c637165673d3d', 3312294332, -356708, '\x67414141414142635679314b6e34685a744c564f6d7036644854456a6b6f6333316c5075376b7a6e3679364343584e74746b5644686b5347426d56504a625272354c6c65354755626750426d4a586b3741326779524353436768534765644b3434513d3d', 45, '$2b$12$45xxxxxxxxxxxxxxxxxxxuNP1qU0EXzry70k27s3PBqFAsMUd9qMu', '$2b$12$MEaNcIqhzbi88XCfxEop0O0M8bHuZkcrMbh0427NDlrxZ4swSCDyC');
INSERT INTO public.device_data (id, tid, added, num_data, data, device_id, tid_bi, correctness_hash) VALUES (25, '\x67414141414142635679314b36534552773452456e714d4e4c46365971424d6d6232773374317971344b736b4b334e394d6e31755f414967324547506e4b47476233542d3963412d717669796b785451376d5f546a62646d6331484748386d535a673d3d', 3317305869, -350734, '\x67414141414142635679314b37636b47357a30556c693951755142796f735a52412d51707335732d5a583541543458796f4855466a4a75754769566f703434534f46617455314962466665455f47745475585a666a4b6e5a524962493642734b77413d3d', 45, '$2b$12$45xxxxxxxxxxxxxxxxxxxuMGd4oU8F3RlsUdmx0CEtLwGOMMmmvKm', '$2b$12$7StzkVHUG6qOUiuackJAj.hrx2ZWBlUP05cS/YS4LHTbHGKZ0wKfK');

INSERT INTO public.user_device (user_id, device_id, device_public_session_key, added) VALUES (1, 23, NULL, NULL);
INSERT INTO public.user_device (user_id, device_id, device_public_session_key, added) VALUES (2, 45, NULL, NULL);
INSERT INTO public.user_device (user_id, device_id, device_public_session_key, added) VALUES (2, 34, NULL, NULL);
INSERT INTO public.user_device (user_id, device_id, device_public_session_key, added) VALUES (2, 37, NULL, NULL);

SELECT pg_catalog.setval('public.acl_id_seq', 19, true);
SELECT pg_catalog.setval('public.action_id_seq', 6, true);
SELECT pg_catalog.setval('public.device_data_id_seq', 26, false);
SELECT pg_catalog.setval('public.device_id_seq', 46, false);
SELECT pg_catalog.setval('public.device_type_id_seq', 1, false);
SELECT pg_catalog.setval('public.mqtt_user_id_seq', 8, true);
SELECT pg_catalog.setval('public.scene_id_seq', 1, false);
SELECT pg_catalog.setval('public.user_id_seq', 3, true);


-- public.device_data.added was converted as `int(time.mktime(parser.parse('2018-12-11 00:00:00+00').timetuple()))`

-- To dump insert statements from database:
-- (You need to be in directory from which you started DB with `docker-compose up`, e.g. `/postgres`)
-- docker exec -it $(docker-compose ps -q ) pg_dump -U<user> --column-inserts --data-only <db_name> > backup.sql
-- docker exec -it $(docker-compose ps -q ) pg_dump -Upostgres --column-inserts --data-only postgres > backup.sql