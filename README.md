IoT Cloud
========================

Privacy friendly framework for IoT Cloud.

## Prerequisites
For server:
- _Docker_
- _docker-compose_

For running tests:
- _Python 3.x_
- _Charm-Crypto_

## Running using Docker
- First follow [steps to bring up PostgreSQL database](postgres/README.md)
- Next, from root directory run: `CURRENT_UID=$(id -u):$(id -g) docker-compose up`
    - _NOTE: `CURRENT_UID=$(id -u):$(id -g)` is necessary because test container needs to run under current user to write reports_ 
- to clean up _\__pycache_\__ and _.pytest\_cache_ directories created by docker use following commands:
    - `sudo find . -path '*/__pycache__*' ! -path "./venv*" -delete`
    - `sudo find . -path '*/.pytest_cache*' ! -path "./venv*" -delete`
    - _NOTE: run commands first without `-delete` flag to test, to make sure you don't damage your system_

### Running tests
- When running tests make sure you set environment variable `TESTING_ENV` to `host_testing`(defaults to `testing`), so the application uses `config.env` variables needed for running tests on host. If not set, tests will run as if they were inside docker container ( = with different URLs).
- To run (from `./tests` directory) use <br> `pytest . --junitxml=./reports/test_report.xml --html=./reports/test_report.html --self-contained-html --cov=../ --cov-config=../.coveragerc --cov-report term`
- To see _HTML_ or _XML_ test and coverage reports check `./tests/reports` directory
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
    
    
## Troubleshooting
- If you have issues running tests inside container (there are some tests that need to be excluded when running inside container), try `docker container prune` and `docker-compose up` again
- If `testing` DB inside docker container is not being created by `create_db.sh`, you need to first remove persistent volume (`docker volume rm iot-cloud_data_test` and `docker volume rm postgres_data`) and prune containers (`docker container prune`)
- if you encounter this error message: `libpbc.so.1: cannot open shared object file: No such file or directory`, make sure you run `ldconfig` after installing _pbc_, if that doesn't help:
    - check whether path to _pbc_ is in `LD_LIBRARY_PATH` (`echo $LD_LIBRARY_PATH `)
    - if not, then run `sudo find / -name libpbc.so`
    - add path outputted by previous command to `LD_LIBRARY_PATH` - e.g. `LD_LIBRARY_PATH=/usr/local/lib` and export it
    - if that solves the issue, add `LD_LIBRARY_PATH` to `~/.bashrc` and `source` it
- if you encounter error message when installing _Charm_ (running `./configure.sh`) stating that you don't have _python3-dev_ or _python3-config_:
    - check whether you have any other version installed e.g _python3.6-config_, if yes, replace occurrence(s) of _python3-config_ in `./configure.sh` with the one you have installed and run it again