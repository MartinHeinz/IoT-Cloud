IoT Cloud
========================

Privacy friendly framework for IoT Cloud.

## Before Running
- Install Mosquitto broker `sudo apt install mosquitto`
- and make it listen on specified port e.g.: `mosquitto -p 1883`
- install `docker-compose`

## Running using Docker
- from root directory run: `docker-compose up`
- to clean up _\__pycache_\__ and _.pytest\_cache_ directories created by docker use following commands:
    - `sudo find . -path '*/__pycache__*' ! -path "./venv*" -delete`
    - `sudo find . -path '*/.pytest_cache*' ! -path "./venv*" -delete`
    - _NOTE: run commands first without `-delete` flag to test, to make sure you don't damage your system_

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

## TLS
It's necessary to provide certificates to use application. When using _Mosquitto_, please use steps at [Mosquitto website](https://mosquitto.org/man/mosquitto-tls-7.html "Mosquitto website")
- Files created in previous steps should be placed in `certs` folder both for _Mosquitto_ and application, replacing `*.dummy` files
- Application currently does not require client certificates, to change that, you need to set `require_certificate true` in `mosquitto.conf` and provide client `certfile` and `keyfile` to `client.tls_set` in `create_app.py` through `CLIENT_CERTFILE_PATH` and `CLIENT_KEYFILE_PATH` config attributes
- in production `SSL_INSECURE` attribute in config should be set to _False_, so when generating certificates, make sure that broker name (hostname) matches name on certificate

## Setting up HTTPS
- You need to provide certificate and key for Nginx server to be accessible - this should be done by replacing dummy files in _./webserver/ssl_ folder 
- To generate self-signed certificate:
    - change directory to _./webserver/ssl_
    - run `sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ./private/webserver.key -out ./certs/webserver.crt`
    
## Running Node-RED
- To start _Node-RED_ with prepared `settings.js` file go to `./node-red` directory and run in using:
    - `./node_modules/node-red/bin/node-red-pi -s ./settings.js` if you have _Node-RED_ installed in `node_modules`
    - `node-red -s ./settings.js` if installed globally