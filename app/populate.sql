TRUNCATE public."user", public.device_type, public.device, public.user_device CASCADE;

INSERT INTO public."user" VALUES (DEFAULT, 'martin', 'martin7.heinz@gmail.com', '5c36ab84439c45a3719644c0d9bd7b31929afd9f', TIMESTAMP '2018-12-24 10:23:54');

INSERT INTO public.device_type (id, type_id, description) VALUES (23525, '12ef8ea3-ba06-4aa9-904e-d5a9f35b09c5', 'raspberry');
INSERT INTO public.device (id, status, device_type_id, name, name_bi) VALUES (23, false, 23525, 'my_raspberry', '$2b$12$1xxxxxxxxxxxxxxxxxxxxuZLbwxnpY0o58unSvIPxddLxGystU.Mq');

INSERT INTO public.device_data (id, added, data, device_id, num_data) VALUES (6, date '2001-03-28', '\\001'::bytea, 23, 66988873); -- 1000
INSERT INTO public.device_data (id, added, data, device_id, num_data) VALUES (8, date '2003-02-13', '\\001'::bytea, 23, 129952183); -- 2000
INSERT INTO public.device_data (id, added, data, device_id, num_data) VALUES (4, date '2004-05-14', '\\001'::bytea, 23, 286346815); -- 4341
INSERT INTO public.device_data (id, added, data, device_id, num_data) VALUES (12, date '2012-09-11', '\\001'::bytea, 23, 195426401); -- 3000

-- To dump insert statements from database:
-- pg_dump -h <host> -U <user> --column-inserts --data-only <db>
-- pg_dump -h localhost -U postgres --column-inserts --data-only flask_test