TRUNCATE public.acl, public.action, public.device, public.device_data, public.device_type, public.mqtt_user, public.scene, public.scene_action, public."user", public.user_device CASCADE;

INSERT INTO public."user" (id, name, email, access_token, access_token_update) VALUES (1, 'MartinHeinz', 'martin7.heinz@gmail.com', '5c36ab84439c45a3719644c0d9bd7b31929afd9f', '2018-12-24 10:23:54');
INSERT INTO public."user" (id, name, email, access_token, access_token_update) VALUES (2, 'TestUser', 'testuser@domain.com', '5c36ab84439c55a3c196f4csd9bd7b319291239f', '2018-12-10 15:12:34');
INSERT INTO public."user" (id, name, email, access_token, access_token_update) VALUES (3, 'TestRunner', 'TestRunner@domain.com', '5c36ab84439c55a3c196f4csd9bd7b3d9291f39g', '2018-12-15 15:12:34');
INSERT INTO public."user" (id, name, email, access_token, access_token_update) VALUES (4, 'TestRunner2', 'TestRunne2r@domain.com', '5c36ab84439gden3c196f4csd9bd7b3d9291f39g', '2018-12-30 15:12:34');

INSERT INTO public.device_type (id, type_id, description, user_id, correctness_hash) VALUES (23525, '12ef8ea3-ba06-4aa9-904e-d5a9f35b09c5', '\x674141414141426359414a6c4e31416e364e63634939492d484239727a47636d4a64334c73736d7361676b5a2d543957634a4a6d376a7a747a57647258346a4c546f635a54647549737077595a4c7149526964394c5536624a496f453475565858673d3d', 1, '$2b$12$Efynt3ipGsBunG4cHNPoTeB6UUYPCvXjfvBOq20UQsgsQvYKcuT4G');
INSERT INTO public.device_type (id, type_id, description, user_id, correctness_hash) VALUES (12452, 'dbb028df-87e7-452d-b160-19e03d93f239', '\x674141414141426359414a6c743165526e6e4e38614754485139715662645537762d61304a694765616e384f31785f6b463457635770416a33633146445031414636556a75686f586274496f4c586658477462694c6f336a4274526f59536f4e39513d3d', 1, '$2b$12$OZn3zWW3g4PfVfG7atrtvebgGwezUPeQOb1xTXFrFJTNnNbwzoheW');

INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi, correctness_hash) VALUES (23, '\x30', 23525, 1, '\x674141414141426359414a6d5f59575a6e66697776333479586c69464e354a576e785232532d726d79664d4c622d6d343532746259496a6959544a6f3239545544325261657135686f576648563874664438643276534f464755797538797a6b54513d3d', '$2b$12$1xxxxxxxxxxxxxxxxxxxxuZLbwxnpY0o58unSvIPxddLxGystU.Mq', '$2b$12$oHkp8uoTUCLF7NJdBOolue4YIaJhle.r.eeQn0i.EfvUHqtCV/rNC');
INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi, correctness_hash) VALUES (45, '\x30', 23525, 2, '\x674141414141426359414a6d6e475a4b6a4b457333375951325f795a467554446850695a486f36446c3561525765326536542d5865466c6e4863754b3878314f6c6e37316952466a725059553931746e6a5a77703434676c49762d4c4b43424359673d3d', '$2b$12$2xxxxxxxxxxxxxxxxxxxxuUvk5iqq7yxVSBXWMofTBLgEj3jXioHu', '$2b$12$ZuD3kAg8fFUSNysn7drwiusv6CdzMZ27gZS745LHOPO9V2brBlCZi');
INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi, correctness_hash) VALUES (34, '\x30', 12452, 2, '\x674141414141426359414a6e495f44453966667239684d79673065536a4b43656e48457a46675367376438504f386943354533636a476671794f33455a75755361754a7a7a41384d784e6a6c5249627635436f574967563668325f5a6170784e4e673d3d', '$2b$12$2xxxxxxxxxxxxxxxxxxxxu9vIxS.wvIOPeYz88BA5e/t3FlezwvUm', '$2b$12$wzmxQfoO.vWMkXbYOcaLHeoPp83aBEF7Br/3GqDTUiVAyDhOe3oS6');
INSERT INTO public.device (id, status, device_type_id, owner_id, name, name_bi, correctness_hash) VALUES (37, '\x30', 12452, 2, '\x674141414141426359414a6e3856444f4f6b4b6d49544762747a5f586e70625271494d64626a3678413530346e44594a6d483446734d2d364177693543635f4e3276392d4d6554384a5f6e4d6c387544415239675f4b663670344a45736d685169413d3d', '$2b$12$2xxxxxxxxxxxxxxxxxxxxu9vIxS.wvIOPeYz88BA5e/t3FlezwvUm', '$2b$12$G7sYdQPOushH1NMsYKji9.i22Y40qxGxoYfr0IX7cKFG14skGN6FS');

INSERT INTO public.mqtt_user (id, username, password_hash, superuser, user_id, device_id) VALUES (1, 'd:23', 'PBKDF2$sha256$10000$a0HFjEn8VZe04CxJ$Zd2UxhyYvlY5wIqycui58jCKVsNxL1MQ', 0, NULL, 23);  -- device1_pass
INSERT INTO public.mqtt_user (id, username, password_hash, superuser, user_id, device_id) VALUES (2, 'u:1', 'PBKDF2$sha256$10000$8dd35yJLqjFIpeMO$oQwtPcs4FhcZGihX71LtN6fm+yVWcb4v', 0, 1, NULL);  -- password1
INSERT INTO public.mqtt_user (id, username, password_hash, superuser, user_id, device_id) VALUES (3, 'd:34', 'PBKDF2$sha256$10000$+tYVrce5IvbOPREB$haW4Atpabx2giJEeDBwaMIvKf3KNNop0', 0, NULL, 34);  -- device3_pass
INSERT INTO public.mqtt_user (id, username, password_hash, superuser, user_id, device_id) VALUES (4, 'd:37', 'PBKDF2$sha256$10000$1RDrXIISPQKSfLvh$HXv5bYEQe7NepGBLmdp6rOydxuETaWNb', 0, NULL, 37);  -- device4_pass
INSERT INTO public.mqtt_user (id, username, password_hash, superuser, user_id, device_id) VALUES (5, 'd:45', 'PBKDF2$sha256$10000$kOVrAa3VULOtlcxS$BP686anaevC7t2hwxCzfvo5UaxOp1+YA', 0, NULL, 45);  -- device2_pass
INSERT INTO public.mqtt_user (id, username, password_hash, superuser, user_id, device_id) VALUES (6, 'u:2', 'PBKDF2$sha256$10000$NsPHhalfv7Asj8mw$jRzH8ZEMh0B5oKPo2vRhcwhvmk0UIPgC', 0, 2, NULL);  -- password2

-- FOR SERVER USER AND DEBUGGING
INSERT INTO public.mqtt_user (id, username, password_hash, superuser) VALUES (7, 'admin', 'PBKDF2$sha256$10000$J8N0E3qluPAwm8uN$n8jehANuh+6ddOtNmopG0Jem79LzV+X4', 1);  -- password
INSERT INTO public.mqtt_user (id, username, password_hash, superuser) VALUES (8, 'testuser', 'PBKDF2$sha256$10000$qu5hXEoBLNeKuzR7$koo7Ozny5dpZE8Vy8GZVi6kcMvWVPrs6', 0);  -- testuser

INSERT INTO acl (id, mqtt_user_id, username, topic, acc) VALUES (17, 8, 'testuser', 'read', 1);
INSERT INTO acl (id, mqtt_user_id, username, topic, acc) VALUES (18, 8, 'testuser', 'write', 2);
INSERT INTO acl (id, mqtt_user_id, username, topic, acc) VALUES (19, 8, 'testuser', 'both', 3);

INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (1, 1, 'u:23', 'u:1/d:23/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (2, 1, 'u:23', 'd:23/u:1/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (3, 1, 'u:23', 'd:23/server/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (4, 1, 'u:23', 'server/d:23/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (5, 2, 'd:1', 'u:1/d:23/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (6, 2, 'd:1', 'd:23/u:1/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (7, 2, 'd:1', 'u:1/server/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (8, 2, 'd:1', 'server/u:1/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (9, 5, 'd:45', 'u:2/d:45/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (10, 5, 'd:45', 'd:45/u:2/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (11, 5, 'd:45', 'd:45/server/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (12, 5, 'd:45', 'server/d:45/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (13, 6, 'u:2', 'u:2/d:45/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (14, 6, 'u:2', 'd:45/u:2/+', 1);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (15, 6, 'u:2', 'u:2/server/+', 2);
INSERT INTO public.acl (id, mqtt_user_id, username, topic, acc) VALUES (16, 6, 'u:2', 'server/u:2/+', 1);

INSERT INTO public.action (id, name, device_id, name_bi, correctness_hash) VALUES (1, '\x674141414141426359414a716a5a794d7451516962474941394e6f5377466b664859594265776a2d6b6c77726754726246676d446c6e38756b37344636546d694c535854514f536262495564307579666166653975385363757a744d635f796859773d3d', 23, '$2b$12$1xxxxxxxxxxxxxxxxxxxxu0K.5ax3yJ0v/fpl9vxvL75NlyxqIOxG', '$2b$12$HhRXtnwZO8yc2DSdHgjL.ORok98m6.3sF6yDhI.uokJSKGoA7uEGC');
INSERT INTO public.action (id, name, device_id, name_bi, correctness_hash) VALUES (2, '\x674141414141426359414a715361557a4872486655397a5751742d394e4b646a4174724358536549505f6a504c6169694b576a414772773972736631546157724d353949427833775445477175564a50646e3972365a66534c763941446c656241413d3d', 23, '$2b$12$1xxxxxxxxxxxxxxxxxxxxuz5Jia.EDkTwFaphV2YY8UhBMcuo6Nte', '$2b$12$o/H4BWhAHD678EHuAYCWB.DkLglRvPML6xhraF37WCD5vW7M8HOTK');
INSERT INTO public.action (id, name, device_id, name_bi, correctness_hash) VALUES (3, '\x674141414141426359414a725f505f38453453306e575446552d7579476b3874334d44657842354c7a4e47484b423672645f70774b7759343162544d5959714176757863724370334242597768374649344636666b73774d4d354a41464d636d71513d3d', 45, '$2b$12$2xxxxxxxxxxxxxxxxxxxxuX8WVpwRXwSKCMut/AzDWhKdjjjSz7VS', '$2b$12$Asm0IjTsgGQwO6efRMORMuUSXirCWwQd871mSjKbwz7ZsUoYtzRe6');
INSERT INTO public.action (id, name, device_id, name_bi, correctness_hash) VALUES (4, '\x674141414141426359414a733877437a7966456448474f3354556a4b2d45655378442d774645674347593858465f6b45786d7474727a556a4d2d59464b55617953726338794c4a4738555865327a4c744772374c50416c35787957373536587363413d3d', 34, '$2b$12$2xxxxxxxxxxxxxxxxxxxxu/OSAIfbWycijeDQl.mejDOu.ceObBVS', '$2b$12$oGbFOkf8fObgY/jnxr3ujeCaPWDxhK2L.TG8dUGpv1ISdHEBGxWhi');
INSERT INTO public.action (id, name, device_id, name_bi, correctness_hash) VALUES (5, '\x674141414141426359414a734a486369387a7a4b45323332505949582d487737346c594e45745f663745636575726f44717030705748474439365f62614c4532746c5165466c4652656e6d706d467774425a51624c4979426641506142586e6c2d413d3d', 37, '$2b$12$2xxxxxxxxxxxxxxxxxxxxu/OSAIfbWycijeDQl.mejDOu.ceObBVS', '$2b$12$DQMJ8iCcXX6RJX0FzrEKu.ABiVQBdYKRtlMsZebhhiNOQF3bV33YW');
INSERT INTO public.action (id, name, device_id, name_bi, correctness_hash) VALUES (6, '\x674141414141426359414a726446544b3167576c4f4b47796e34514357436f7a4171795242686451517078536c486637495a74374e2d37324273376143664e4c4a7432446c38737a5265506b774d546654785f6136484c746c31423155534f5148673d3d', 45, '$2b$12$2xxxxxxxxxxxxxxxxxxxxu/YL3iUR.GmOBP7qmFnisZpldYQowgna', '$2b$12$CLrsGDGi1893iYDExzjH1eGDmdQirvCzmaS38chtjIG4nZDnWP.Qe');

INSERT INTO public.device_data (id, tid, added, num_data, data, device_id, tid_bi, correctness_hash) VALUES (6, '\x674141414141426359414a74705855646f756463436e696e6e62776b63686b38453448525f54693570764d664736756a443331563067764c765a4e3072416a693239397432394f354d45355863725a4f44304b653879324741646b413339374531413d3d', 2116580122, 464064, '\x674141414141426359414a74464779667638764d7a6e6d5859427668415a58694d6b794e545975327957394e70385361435a43677345516c6e396a74645252774f50356b6b2d506959587366694a616c77582d44586c562d5361684f786e726b58673d3d', 23, '$2b$12$23xxxxxxxxxxxxxxxxxxxuN5X.DMkHilBYQSsUWodebAG.asbqKNa', '$2b$12$fqCMOJGcp5cCr5PRtzMyme4moN9Sj.CfvaAB3qWYSHwOTPRh5cTwG');
INSERT INTO public.device_data (id, tid, added, num_data, data, device_id, tid_bi, correctness_hash) VALUES (8, '\x674141414141426359414a74774b7139565f6c773738476d79754a495545374b476b6e71377a4a632d5f686135617862705646554445513258685a6c535966575563476648374632627164754b46354b59704f3749647646434963445053614c79773d3d', 2244039737, 466263, '\x674141414141426359414a74594b6f6643515a31534c46494f5f30477a4b7a5a72786848365f5545676d5864387a584f6f656d346877395533634c527448387268657874695473575f624f726e666433306c53616a464d6761366d7a474b653668773d3d', 23, '$2b$12$23xxxxxxxxxxxxxxxxxxxu.ZfhXcDxDatkjrxC5f7I1S9D0G9uMI.', '$2b$12$ZNB6MgGq8kNx8XH5.QYUQOcr7ksSKfAI55Br/tVlixRmOAikvnomS');
INSERT INTO public.device_data (id, tid, added, num_data, data, device_id, tid_bi, correctness_hash) VALUES (4, '\x674141414141426359414a744e41327564734b4f6e46575162744544314779362d51556c44706356326d354a4438397347514e33794a37344977424a6a3279654e31694e4469594b5773746c576e4330696b324c73364336634337674d55593869673d3d', 2328646538, 471232, '\x674141414141426359414a745464554734545f616b6e51324c507868464c455745354e726c75776554656c3669584e31545151336c366b74717770686472384f324e2d6239727964793476544e6858654b7542766c5834546e4743657350454442773d3d', 23, '$2b$12$23xxxxxxxxxxxxxxxxxxxuSfVK9H/a.JO/whZHvsU1Q39d26XzS/6', '$2b$12$owSqcsIDoEqQzwgNowqcf.Az4aU8NIPFX1YeU2DRI6TT32o1zPJ7e');
INSERT INTO public.device_data (id, tid, added, num_data, data, device_id, tid_bi, correctness_hash) VALUES (12, '\x674141414141426359414a74304d57757a774c685459576a323856683046424e52467856455278316239453831625f76304a7936633075436453365f787a78444b337a4535352d664b6c35383138543357314d7a71714247505567703746553052773d3d', 2893054513, 468360, '\x674141414141426359414a7444695776685473525177695a433248474f495a524135455a58744749627a58426679413342616630716e466d455a4a657231714961554f37316b64474c4132534966656c334c44626f78716a534474414a534d5f68513d3d', 23, '$2b$12$23xxxxxxxxxxxxxxxxxxxupooniyevX3UXhzktSF2tYwePP7PnQ6C', '$2b$12$hddICvLddNPSI3D9V5inlOnm3WN7KLbWNrAUMJtrkrYIZ38rbUtSC');
INSERT INTO public.device_data (id, tid, added, num_data, data, device_id, tid_bi, correctness_hash) VALUES (24, '\x674141414141426359414a74314b55556e6b3069663066303356772d4d6b543648326c54784f51306c413842304155747234714a5a547273684b314134344932573434367631677277724c7031555a58333575382d516131422d2d49386e674147513d3d', 3312294332, -356708, '\x674141414141426359414a7475374d584c536732733739626f53324273447757596d545a68474f705039534d3877446f566866467a67314f73356346784b72644f4d70626e5f645a4a307a764a79344c50684a6f6d375452784b7532635f6d5077513d3d', 45, '$2b$12$45xxxxxxxxxxxxxxxxxxxuNP1qU0EXzry70k27s3PBqFAsMUd9qMu', '$2b$12$duW3I7XNWbMoKoN6NVo56.z77VZrFnkdYapkGXXWPFm6E.JPXIPKi');
INSERT INTO public.device_data (id, tid, added, num_data, data, device_id, tid_bi, correctness_hash) VALUES (25, '\x674141414141426359414a743849446631626c7743317a615942516b326c4a622d41544a39755832445857766c534763486f516c344b3477563676764d336d5561306c77447674344752786e746b56346a5a59547a637969534d39455173595165413d3d', 3317305869, -350734, '\x674141414141426359414a7476535666643777397168716d69634f636b6358504a33313964586d6a7a5338574b584f70302d7a73394372584c773862527948327449695472354a6b31754f4c446c70344853595745424278334c68353735456c4c673d3d', 45, '$2b$12$45xxxxxxxxxxxxxxxxxxxuMGd4oU8F3RlsUdmx0CEtLwGOMMmmvKm', '$2b$12$/7.J9yJ.U4huS7.MJduzbOGJ0jFkog3RFb19S1Ta3LaRvQz4ERCgS');

INSERT INTO public.scene (id, name, description, correctness_hash, name_bi) VALUES (1, '\x674141414141426359414a70367753725354636867336b616f4766706d746968475a4c4c784a37595f5a7853446c67593771616133554b362d37645a464c31343239557649683039795f456e4a3358396458485470727156726536735670414d51513d3d', '\x674141414141426359414a70593954316b4e4c3265692d686b7a6d346e467a436a7078554e39734e774436517a334e5763425556756d6548314238797646414c6f677a364d2d785f305431436876784d7545502d5744305731344b4c6f57736334304357736a6b647548634858676b5467347a484d67513d', '$2b$12$46M.LQQ53MUXONgH74K3MuaegzetgAPL/x1d6cQnJv05l8iY0xh6q', '$2b$12$1xxxxxxxxxxxxxxxxxxxxuu6vgMFXlStkb/wcrduAWfPJXkjFPowS');
INSERT INTO public.scene (id, name, description, correctness_hash, name_bi) VALUES (2, '\x674141414141426359414a6f484f56666872453458356459447767503478583132697239663768327832374a5a43586e3533545231314c676f58356365424e4e58446335747946332d426f357859435f5865746e54524c2d50503243376a6b4c6b673d3d', '\x674141414141426359414a6f625f6a5763437857546271674656573861705267624d78343041684374576348796f3750466c3579775a45325134474e7157325a37694a696d5378366d7533307a663654547a4c4e79592d5a7566684f436861707a5443476e5246733363677a344e3871447256796830727068696a71343551515a44462d4849714b4872576d', '$2b$12$O9921l/tEoDsiYq32BEyHOGiHFltQmApCblBrvXyVY8mo9TAY5a3W', '$2b$12$2xxxxxxxxxxxxxxxxxxxxuFf6FbODZ2N76WZRFjGnVHEA8kZXP.U2');
INSERT INTO public.scene (id, name, description, correctness_hash, name_bi) VALUES (3, '\x674141414141426359414a6f486f6e3776324c4c4f524a4e525830334b4f57545471756d597973336449616c38322d534b4a5763436131385434386a4e57533572395f524a6e7a462d31506635673339314141722d4a6965386c6a6342466f3868673d3d', '\x674141414141426359414a6f46454678534d4c4b6a6e3567633059362d4a4b7249726c316e4d7a3866567a34527766594f56417950364e746e33647573656f66337a564e61593246325f45305a70703056735f4e50724d6f66774742787465703548696b765f76526342704271727a72396154355961723664483366415a364f304d4a6f34526a3779696245', '$2b$12$7nYf1b//gjtlCrKfaeY7WOgIWuUbC/hu8K3BCUH2ssJtMV7RMFEfO', '$2b$12$2xxxxxxxxxxxxxxxxxxxxuwsiAgo8fzpMIz1qcBwfHAl71etW9umO');

INSERT INTO public.scene_action (scene_id, action_id) VALUES (2, 5);
INSERT INTO public.scene_action (scene_id, action_id) VALUES (3, 6);
INSERT INTO public.scene_action (scene_id, action_id) VALUES (1, 1);
INSERT INTO public.scene_action (scene_id, action_id) VALUES (3, 4);
INSERT INTO public.scene_action (scene_id, action_id) VALUES (2, 4);
INSERT INTO public.scene_action (scene_id, action_id) VALUES (2, 3);

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
SELECT pg_catalog.setval('public.scene_id_seq', 3, true);
SELECT pg_catalog.setval('public.user_id_seq', 3, false);


-- public.device_data.added was converted as `int(time.mktime(parser.parse('2018-12-11 00:00:00+00').timetuple()))`

-- To dump insert statements from database:
-- (You need to be in directory from which you started DB with `docker-compose up`, e.g. `/postgres`)
-- docker exec -it $(docker-compose ps -q ) pg_dump -U<user> --column-inserts --data-only <db_name> > backup.sql
-- docker exec -it $(docker-compose ps -q ) pg_dump -Upostgres --column-inserts --data-only postgres > backup.sql