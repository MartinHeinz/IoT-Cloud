TRUNCATE public.acl, public.action, public.device, public.device_data, public.device_type, public.mqtt_user, public.scene, public.scene_device, public."user", public.user_device CASCADE;

INSERT INTO public."user" (id, name, email, access_token, access_token_update) VALUES (1, 'MartinHeinz', 'martin7.heinz@gmail.com', '5c36ab84439c45a3719644c0d9bd7b31929afd9f', '2018-12-24 10:23:54');
INSERT INTO public."user" (id, name, email, access_token, access_token_update) VALUES (2, 'TestUser', 'testuser@domain.com', '5c36ab84439c55a3c196f4csd9bd7b319291239f', '2018-12-10 15:12:34');
INSERT INTO public."user" (id, name, email, access_token, access_token_update) VALUES (3, 'TestRunner', 'TestRunner@domain.com', '5c36ab84439c55a3c196f4csd9bd7b3d9291f39g', '2018-12-15 15:12:34');
INSERT INTO public."user" (id, name, email, access_token, access_token_update) VALUES (4, 'TestRunner2', 'TestRunne2r@domain.com', '5c36ab84439gden3c196f4csd9bd7b3d9291f39g', '2018-12-30 15:12:34');

INSERT INTO public.device_type (id, type_id, description, user_id, correctness_hash) VALUES (23525, '12ef8ea3-ba06-4aa9-904e-d5a9f35b09c5', '\x674141414141426358654a713155734f336e616c3333587231504c485f34414a75676a6e48536d31615651684f77434a574a454b554a3368497a54544130556f7a46324b56335937386276376642784859694b4a5452455a31397834714f327a4a413d3d', 1, '$2b$12$nvgzOX8UiEXS7R4.P0KosOllptS9PHRqEuFSsP3lUnCFkkisrpYRu');
INSERT INTO public.device_type (id, type_id, description, user_id, correctness_hash) VALUES (12452, 'dbb028df-87e7-452d-b160-19e03d93f239', '\x674141414141426358654a717755416b7a50734a38435f483263346b384d656537506832734d725f634a4e476b735459795f342d45487a48666e635431394d4c6a634644754d50747548354d4656306964745271544d2d44494f71656755644a4e773d3d', 1, '$2b$12$U3j8u8JNvZ2sQeus5AV2H.MAnwiSQSy7efmXr9RPdVjKVVu7q3lAG');

INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi, correctness_hash) VALUES (23, '\x30', 23525, 1, '\x674141414141426358654a71494e6e48505454754641354935446c374453306a485a4c5f62393868414774774657686578523241705a79582d47454f5a64664f66556f5a435f4678573851454c70334a724d2d79515369474f454764654831766a413d3d', '$2b$12$1xxxxxxxxxxxxxxxxxxxxuZLbwxnpY0o58unSvIPxddLxGystU.Mq', '$2b$12$sDgS8g8.kMODUAp9G2ZBeeqdMmKBDoGWF4yrdQ0OPbIytvX8R9HvC');
INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi, correctness_hash) VALUES (45, '\x30', 23525, 2, '\x674141414141426358654a723130574b506b73662d4e474d61376836346f354e475548355a324f476a4a503532726c33505751793272456d4d694f7657795075782d352d324762656e466f77364d6b413431495243767576566a58505f5745474c673d3d', '$2b$12$2xxxxxxxxxxxxxxxxxxxxuUvk5iqq7yxVSBXWMofTBLgEj3jXioHu', '$2b$12$6Zcm0ORbDXxGPz67POFb/OsY8g1HQhGp7ZHbE18H5QgtD.tjVh.W.');
INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi, correctness_hash) VALUES (34, '\x30', 12452, 2, '\x674141414141426358654a72437332794c58444b764573305630655038527552383546444748666c564b5171727351326b484e357a6e7133387178355a4d4a4c4e626d45644f6d61625744444e71666752576c516e736338524f575765674e6a37513d3d', '$2b$12$2xxxxxxxxxxxxxxxxxxxxu9vIxS.wvIOPeYz88BA5e/t3FlezwvUm', '$2b$12$Bm7YB387UHQDT83Ttg5A/.mP1kcbUBVjmsgwuoajVYSho2fZI7n1e');
INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi, correctness_hash) VALUES (37, '\x30', 12452, 2, '\x674141414141426358654a73725a37575f667a514d32725751647255496e64376e45676a386341623079336541476f79715862556a774d532d78464676413739637a7a694e76626f4637314a7461304c5936776934546b5a49514e674668496975513d3d', '$2b$12$2xxxxxxxxxxxxxxxxxxxxu9vIxS.wvIOPeYz88BA5e/t3FlezwvUm', '$2b$12$.QCokOn1pDlNDcwFb4BaBeQvj5NUTBJiTqYqMrnLTr41mmWCJ2Bb.');

INSERT INTO public.mqtt_user (id, username, password_hash, superuser, user_id, device_id) VALUES (1, '23', 'PBKDF2$sha256$10000$a0HFjEn8VZe04CxJ$Zd2UxhyYvlY5wIqycui58jCKVsNxL1MQ', 0, NULL, 23);  -- device1_pass
INSERT INTO public.mqtt_user (id, username, password_hash, superuser, user_id, device_id) VALUES (2, '1', 'PBKDF2$sha256$10000$8dd35yJLqjFIpeMO$oQwtPcs4FhcZGihX71LtN6fm+yVWcb4v', 0, 1, NULL);  -- password1
INSERT INTO public.mqtt_user (id, username, password_hash, superuser, user_id, device_id) VALUES (3, '45', 'PBKDF2$sha256$10000$kOVrAa3VULOtlcxS$BP686anaevC7t2hwxCzfvo5UaxOp1+YA', 0, NULL, 45);  -- device2_pass
INSERT INTO public.mqtt_user (id, username, password_hash, superuser, user_id, device_id) VALUES (4, '34', 'PBKDF2$sha256$10000$+tYVrce5IvbOPREB$haW4Atpabx2giJEeDBwaMIvKf3KNNop0', 0, NULL, 34);  -- device3_pass
INSERT INTO public.mqtt_user (id, username, password_hash, superuser, user_id, device_id) VALUES (5, '37', 'PBKDF2$sha256$10000$1RDrXIISPQKSfLvh$HXv5bYEQe7NepGBLmdp6rOydxuETaWNb', 0, NULL, 37);  -- device4_pass
INSERT INTO public.mqtt_user (id, username, password_hash, superuser, user_id, device_id) VALUES (6, '8', 'PBKDF2$sha256$10000$NsPHhalfv7Asj8mw$jRzH8ZEMh0B5oKPo2vRhcwhvmk0UIPgC', 0, 2, NULL);  -- password2

-- FOR SERVER USER AND DEBUGGING
INSERT INTO public.mqtt_user (id, username, password_hash, superuser) VALUES (7, 'admin', 'PBKDF2$sha256$10000$J8N0E3qluPAwm8uN$n8jehANuh+6ddOtNmopG0Jem79LzV+X4', 1);  -- password
INSERT INTO public.mqtt_user (id, username, password_hash, superuser, user_id) VALUES (8, 'testuser', 'PBKDF2$sha256$10000$qu5hXEoBLNeKuzR7$koo7Ozny5dpZE8Vy8GZVi6kcMvWVPrs6', 0, 2);  -- testuser

INSERT INTO acl (id, mqtt_user_id, username, topic, acc) VALUES (17, 8, 'testuser', 'read', 1);
INSERT INTO acl (id, mqtt_user_id, username, topic, acc) VALUES (18, 8, 'testuser', 'write', 2);
INSERT INTO acl (id, mqtt_user_id, username, topic, acc) VALUES (19, 8, 'testuser', 'both', 3);

INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (1, 1, '23', 'u:1/d:23/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (2, 1, '23', 'd:23/u:1/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (3, 1, '23', 'd:23/server/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (4, 1, '23', 'server/d:23/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (5, 2, '1', 'u:1/d:23/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (6, 2, '1', 'd:23/u:1/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (7, 2, '1', 'u:1/server/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (8, 2, '1', 'server/u:1/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (9, 3, '45', 'u:2/d:45/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (10, 3, '45', 'd:45/u:2/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (11, 3, '45', 'd:45/server/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (12, 3, '45', 'server/d:45/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (13, 6, '8', 'u:2/d:45/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (14, 6, '8', 'd:45/u:2/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (15, 6, '8', 'u:2/server/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (16, 6, '8', 'server/u:2/+', 1);

INSERT INTO public.action (id, name, device_id, name_bi, correctness_hash) VALUES (1, '\x674141414141426358654a7343457349456b595267524b4f4945777a496b4f576e365f677864776978326a566d3372694275644f5a694b69515a384c493034784b4754556e71633854767331524665704e4971774d41776c5f674a7a626c354457413d3d', 23, '$2b$12$1xxxxxxxxxxxxxxxxxxxxu0K.5ax3yJ0v/fpl9vxvL75NlyxqIOxG', '$2b$12$rpAGH.w5STsSv3R/h2UkZ.Ij9EfoIDmPQhW50p.J83tL24N5Dl646');
INSERT INTO public.action (id, name, device_id, name_bi, correctness_hash) VALUES (2, '\x674141414141426358654a734243584831364f6b6f335a4867765a30466139516866514162387a494b5457727337745954643161413746413765325358375a66354b75392d79436651527558595671353333434f395f616e5336535930354d3845513d3d', 23, '$2b$12$1xxxxxxxxxxxxxxxxxxxxuz5Jia.EDkTwFaphV2YY8UhBMcuo6Nte', '$2b$12$yMwIDET0kTtYqHCJUWCXXu3Bks7v8BkIXmpk3XCyMZ7KjfNVGmaBi');
INSERT INTO public.action (id, name, device_id, name_bi, correctness_hash) VALUES (3, '\x674141414141426358654a7450673155305645775635576856562d5f596e6167356249304c72516641634c6a6e546d784a59487a365a5775696870564a686f37736d6554594257674b335346314b30644a316b7136715564366a34417568524e58513d3d', 45, '$2b$12$2xxxxxxxxxxxxxxxxxxxxuX8WVpwRXwSKCMut/AzDWhKdjjjSz7VS', '$2b$12$ockM67tKoozrFOaQ5486y.unS4iryVfG8jeoxNrQ9mAa/lS.YfN7e');
INSERT INTO public.action (id, name, device_id, name_bi, correctness_hash) VALUES (4, '\x674141414141426358654a74675373584a7467687347676c42663434694276735031375673504b744e51536669705f6e6a6d6c4d4f6133337035796c66307174597251764c5f515f4c3877414b4c3963546372634e754857564f504b5045576d73413d3d', 45, '$2b$12$2xxxxxxxxxxxxxxxxxxxxu/YL3iUR.GmOBP7qmFnisZpldYQowgna', '$2b$12$mFoBNnB9J6wNJZyt.BGEl.oWZAT1kxpGX0wrrh3nXb9a2dXq2t/vW');
INSERT INTO public.action (id, name, device_id, name_bi, correctness_hash) VALUES (5, '\x674141414141426358654a7633446c7868756c66796569456f526a79783151446764527a333177687442536330766a306a7842716f6d48716d4a6130784f4a45773856375439535a34437158502d6b2d686d616654715745615164586248663476513d3d', 34, '$2b$12$2xxxxxxxxxxxxxxxxxxxxu/OSAIfbWycijeDQl.mejDOu.ceObBVS', '$2b$12$8BLbrQJNHCxHFdvsD9VxU.pnZS0E8f8oBKqdOcB9hhWj4pg3uXDpy');
INSERT INTO public.action (id, name, device_id, name_bi, correctness_hash) VALUES (6, '\x674141414141426358654a7649316c6c585948475246635f56427030537537354d75775f6d79326d46394f5f7144634b506c6c6259585a714a4730645665586652584a53345a6441414a56762d65684d397a7a4536593671714a7068615549766d773d3d', 37, '$2b$12$2xxxxxxxxxxxxxxxxxxxxu/OSAIfbWycijeDQl.mejDOu.ceObBVS', '$2b$12$YVp5DQRVRPBILEsIlMAPT.R4YP.5aJ4E/oPMkpXjhH1ePtdy5/Zf2');

INSERT INTO public.device_data (id, tid, added, num_data, data, device_id, tid_bi, correctness_hash) VALUES (6, '\x674141414141426358654a776c38475f714e76784c6b4a75504a5f2d6467356549504433475f43482d555450554d74326139395f4331746778426b342d6a4b6f694f50664c4b56377a70516c64764e365451786b4b3066594d6d597a34515f5a45513d3d', 2116580122, 464064, '\x674141414141426358654a7752597733726f31664d656c725662363976487457347647373137487678397a524843735f33795079356674744c4c78776f545046366a754b39756b7262577055437331774334525a66323049484c664a4b4b616a4a773d3d', 23, '$2b$12$23xxxxxxxxxxxxxxxxxxxuN5X.DMkHilBYQSsUWodebAG.asbqKNa', '$2b$12$yavDyvDbNnQhzXprdLuHAOSmtPb5vTX6hVJbDzLVW42MnKodEoKHu');
INSERT INTO public.device_data (id, tid, added, num_data, data, device_id, tid_bi, correctness_hash) VALUES (8, '\x674141414141426358654a7775654f484f5744434c64677730315a575334396c3539764c436a627364622d42796c2d574975374e754e6c6f76704a6d4c32597849575f476b6569496c6b5073485a59544571737934525449344d4e754434475739773d3d', 2244039737, 466263, '\x674141414141426358654a777863436e6a687879582d676565537677486f455455682d593237786130564834315f306c4d5a416a355151387744426c7a52465437327869614462772d5977374b61504e713263347a45646e794d44504b73535343413d3d', 23, '$2b$12$23xxxxxxxxxxxxxxxxxxxu.ZfhXcDxDatkjrxC5f7I1S9D0G9uMI.', '$2b$12$tdEucCN6WSn5AFNyyoPuQe.Ij2pBEOBehrSHKPfnMNv4WMIAAZpAq');
INSERT INTO public.device_data (id, tid, added, num_data, data, device_id, tid_bi, correctness_hash) VALUES (4, '\x674141414141426358654a77493151426e77535a3866346c5f66496e4d555856674f466a4e59517859474f304d46593078524e3235754873435974536e3652475a7869752d6b544963502d5f4c6a68512d6a35466d5a646c4c3851526148756275773d3d', 2328646538, 471232, '\x674141414141426358654a77724136714958695756504d5a414654376e38566245752d5f7473394a35356a56785333434b765350584679754d6b56694e5a706d62374c656f4e4b725176686348346b544476316451654e312d6a5a615130705343413d3d', 23, '$2b$12$23xxxxxxxxxxxxxxxxxxxuSfVK9H/a.JO/whZHvsU1Q39d26XzS/6', '$2b$12$tnGTizXqjjhHg3PGAeJ3Ne3QjtDsQPzvQ5swkQ43oZRAW4z1HEfLC');
INSERT INTO public.device_data (id, tid, added, num_data, data, device_id, tid_bi, correctness_hash) VALUES (12, '\x674141414141426358654a7779574e70454c4c43574e7363453831796758334975597646506871357267774a575f4a4736644e583356766b686b42497a4f46505965425f65757a4b4f4b6e75696e41446862585065347a77595777613466374e79413d3d', 2893054513, 468360, '\x674141414141426358654a77306c37386e37345f584f4277547559562d715459576f57616e4134634376327341494955562d326637536432394c72334f2d744753494650615f50707a4a3338754e516e746958796e4a4b454962564f3567467132673d3d', 23, '$2b$12$23xxxxxxxxxxxxxxxxxxxupooniyevX3UXhzktSF2tYwePP7PnQ6C', '$2b$12$T61Q0eqC/.JJ6kbGDYUaAuAz1Jd5b8FHZRqvhd74extpnpzAfuUdS');
INSERT INTO public.device_data (id, tid, added, num_data, data, device_id, tid_bi, correctness_hash) VALUES (24, '\x674141414141426358654a777279363455776d3056364642613070396933577835445f6f363167463947524848567946684e316e4154314e6475766d3234475f4e4e61764b49386e4c2d6e502d674476517752626431643374676e443041365449513d3d', 3312294332, -356708, '\x674141414141426358654a77364c4e386c5749674d4c4e684f73544937317177733070635565484b574454364a653950744d4c62637371656f545169327344795f385372696b45357048442d585a646134374e48544d734272534c583162303551673d3d', 45, '$2b$12$45xxxxxxxxxxxxxxxxxxxuNP1qU0EXzry70k27s3PBqFAsMUd9qMu', '$2b$12$i1l2NWC6qFHOe.Ei/NniT.LQfBKRLFs2H9lLpD7nJy4mJAjMIvUB6');
INSERT INTO public.device_data (id, tid, added, num_data, data, device_id, tid_bi, correctness_hash) VALUES (25, '\x674141414141426358654a7736666b5a32456c62794164344777785574343658336d3951694f6c4272767642313365633362304c6a6f5947472d773532756b4a717379562d765077476f69507a6c3675754f494c5849614238585549436f4c6e32513d3d', 3317305869, -350734, '\x674141414141426358654a77466b444e576945624e3659514b514e4b6c396d6a34643452494c4f777833707572637358444439456d7a6d69414c594d74467a6e4952746f62484b53707775716234776d44696f387a493155516330674f7877536a773d3d', 45, '$2b$12$45xxxxxxxxxxxxxxxxxxxuMGd4oU8F3RlsUdmx0CEtLwGOMMmmvKm', '$2b$12$pfHuSkEEfK5Mr6xI1dE52.HGf9eMACTI0SoYFiGSF0klEzDaF47Xm');

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