TRUNCATE public."user", public.device_type, public.device, public.user_device CASCADE;

INSERT INTO public."user" VALUES (DEFAULT, 'martin'), (DEFAULT, 'jozo'), (DEFAULT, 'fero');

INSERT INTO public.device_type (id, type_id, description) VALUES (1, '12ef8ea3-ba06-4aa9-904e-d5a9f35b09c5', 'raspberry');
INSERT INTO public.device (id, status, device_type_id) VALUES (1, false, 1);

-- To dump insert statements from database:
-- pg_dump -h <host> -U <user> --column-inserts --data-only <db>
-- pg_dump -h localhost -U postgres --column-inserts --data-only flask_test