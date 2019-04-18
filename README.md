IoT Cloud
========================

Privacy friendly framework for IoT Cloud.

In this repository you can find server application (`app` directory) and client for both user (`client/user`)
and device (`client/device` and `node-red`) for the framework. For more information, please see my [Diploma Paper](http://davinci.fmph.uniba.sk/~heinz4/diplomova_praca/diploma_heinz.pdf).

## Prerequisites
For server:
- _Docker_
- _docker-compose_

For running tests:
- _Python 3.x_
- _PBC_
- _Charm-Crypto_

## Additional information
For more information about each module, please see _READMEs_ in other modules:
* [postgres/README.md](postgres/README.md)
* [node-red/README.md](node-red/README.md)
* [benchmark/README.md](benchmark/README.md)
* [client/README.md](client/README.md)


## Setting up certificates
- You need to provide certificate and key for Nginx server to be accessible - this should be done by replacing dummy files in _./webserver/ssl_ folder 
- To generate self-signed certificate:
    - change directory to _./webserver/ssl_
    - run `sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ./private/webserver.key -out ./certs/webserver.crt`
    - copy `webserver.crt` to `./app/resources/` and rename to `server.crt`
    - copy `webserver.crt` to `./mosquitto/certs/server/` and rename to `server.crt`
    - copy `webserver.key` to `./mosquitto/certs/server/` and rename to `server-nopass.key`
    - copy `webserver.key` to `./client/user/certs/` and rename to `server.key`

## Running using Docker
- First follow [steps to bring up PostgreSQL database](postgres/README.md)
- Next, get images: `docker-compose pull`
- Create `./app/config.env` based on `config.env.sample`
- Create `data` and `log` folder in `mosquitto` folder (folders have to have same access rights as logged in user)
- Next, from root directory run: `CURRENT_UID=$(id -u):$(id -g) docker-compose up`
    - _NOTE: `CURRENT_UID=$(id -u):$(id -g)` is necessary because test container needs to run under current user to write reports_ 
- to clean up _\__pycache_\__ and _.pytest\_cache_ directories created by docker use following commands:
    - `sudo find . -path '*/__pycache__*' ! -path "./venv*" -delete`
    - `sudo find . -path '*/.pytest_cache*' ! -path "./venv*" -delete`
    - _NOTE: run commands first without `-delete` flag to test, to make sure you don't damage your system_

### Running tests
- Before running tests:
    * create python `venv` and activate it
    * run ```
    apt-get -y --allow-unauthenticated install
    python-psycopg2
    libpq-dev
    flex
    bison
    libgmp3-dev
    libpq-dev``` (This is for _Ubuntu_, for other distros use alternative libraries)
    * install PBC:
    ```
    wget http://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
    tar xf pbc-0.5.14.tar.gz
    cd pbc-0.5.14
    ./configure && make && sudo make install
    ```
    * install _Charm-Crypto_:
    ```
    cd venv
    git clone https://github.com/JHUISI/charm.git
    cd charm/
    ./configure.sh
    make install
    sudo ldconfig
    ```
    * install requirements - `pip install -r requirements.txt`
    * Next, follow steps in previous section (_Running using Docker_)
- Set environment variable `TESTING_ENV` to `host_testing`(, `export TESTING_ENV=host_testing`, defaults to `testing`), so the application uses `config.env` variables needed for running tests on host. If not set, tests will run as if they were inside docker container ( = with different URLs).
- To run (from `./tests` directory) use <br> `pytest . --junitxml=./reports/test_report.xml --html=./reports/test_report.html --self-contained-html --cov=../ --cov-config=../.coveragerc --cov-report term`
    * This generates XML and HTML test reports and prints simple coverage report to terminal
    * To see full HTML coverage report use `--cov-report=html` instead of `--cov-report term`, which creates whole directory (`cov_report.html`) which contains
    graphical coverage report for each file in project
- To see _HTML_ or _XML_ test and coverage reports check `./tests/reports` directory
- _NOTE: When running tests on Docker host it's necessary to have server application running, because CLI tests are ran against this instance_
- _NOTE #2: These test runs modify DB, so when using server application, it's always better to work with fresh app (with no test runs)._

## Certificates and security
All of the _READMEs_ here assume usage of self-signed certificates which are not secure, in any publicly available environment,
therefore all certificates should be created using `certbot`. <br>

In publicly available environment these values should be changed:
- set `require_certificate true` in `mosquitto.conf` and provide client `certfile` and `keyfile` to `client.tls_set` in `create_app.py` through `CLIENT_CERTFILE_PATH` and `CLIENT_KEYFILE_PATH` config attributes
- set `SSL_INSECURE` attribute in config to `False`, and when generating certificates, make sure that broker name (hostname) matches name on certificate

## Troubleshooting
- If you have issues running tests inside container (there are some tests that need to be excluded when running inside container), try `docker container prune` and `CURRENT_UID=$(id -u):$(id -g) docker-compose up` again
- If `testing` DB inside docker container is not being created by `create_db.sh`, you need to first remove persistent volume (`docker volume rm iot-cloud_data_test` and `docker volume rm postgres_data`) and prune containers (`docker container prune`)
- if you encounter this error message: `libpbc.so.1: cannot open shared object file: No such file or directory`, make sure you run `ldconfig` after installing _pbc_, if that doesn't help:
    - check whether path to _pbc_ is in `LD_LIBRARY_PATH` (`echo $LD_LIBRARY_PATH `)
    - if not, then run `sudo find / -name libpbc.so`
    - add path outputted by previous command to `LD_LIBRARY_PATH` - e.g. `LD_LIBRARY_PATH=/usr/local/lib` and export it
    - if that solves the issue, add `LD_LIBRARY_PATH` to `~/.bashrc` and `source` it
- if you encounter error message when installing _Charm_ (running `./configure.sh`) stating that you don't have _python3-dev_ or _python3-config_:
    - check whether you have any other version installed e.g _python3.6-config_, if yes, replace occurrence(s) of _python3-config_ in `./configure.sh` with the one you have installed and run it again