IoT Cloud
========================

Privacy friendly framework for IoT Cloud.

## Before Running
- Install Mosquitto broker `sudo apt install mosquitto`
- and make it listen on specified port e.g.: `mosquitto -p 1883`
- install `docker-compose`

## Running using Docker
- from root directory run: `docker-compose up`

## Running using Flask
- export path to flask application factory method - `export FLASK_APP="app.app_setup:create_app('development')"`
- run from `./IoT-Cloud/app` directory with command `flask run`

## Testing communication between broker and app
- install `sudo apt install mosquitto-clients`
- publish to topics to which application is subscribed to by using `mosquitto_pub -h <host> -p <port> -t <topic_name> -m "message"`

## Accessing database
- you can access database using _pgadmin4_
- login to `psql` using `sudo -u postgres psql`
- find `postgresql.conf` and `pg_hba.conf` using `show config_file;` and `show hba_file;` respectively
- in `postgresql.conf` set listen address to `listen_addresses = '*'` to allow remote access
- in `pg_hba.conf` add after localhost line: <code>host&nbsp;&nbsp;&nbsp;&nbsp;all&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;all&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0.0.0.0/0&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;md5</code>
- restart _postgres_ service - `sudo service postgresql stop` and `sudo service postgresql start`
- steps based on [This blog](https://blog.jsinh.in/how-to-enable-remote-access-to-postgresql-database-server/#.VZqPgnXInK5 "This blog")

## Modifying database inside container
- `docker exec -it $(docker-compose ps -q db ) psql -Upostgres -c '\z'`  to show all tables in the database. In another terminal, talk to the container's Postgres
- `docker exec -it $(docker-compose ps -q db ) psql -Upostgres -c 'create table user()'` to write queries directly

- `docker exec -it $(docker-compose ps -q db ) pg_dump -Upostgres > backup.sql`  to dump (backup) data to host
- `docker exec -i $(docker-compose ps -q db ) psql -Upostgres < backup.sql`  to restore backed up data
- based on [StackOverflow answer](https://stackoverflow.com/questions/35679995/how-to-use-a-postgresql-container-with-existing-data "StackOverflow answer")

- Preferably access using _pgadmin4_ should be used with username _postgres_ and exposed port from _docker-compose.override_ (by default: `5431`)