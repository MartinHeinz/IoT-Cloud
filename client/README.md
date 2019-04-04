## User CLI

This is directory that contains source code responsible for CLI for user to interact with server, broker and devices.

### Prerequisites
* _Python 3.6_
* _Charm Crypto_ (<https://jhuisi.github.io/charm/install_source.html>)

### Install
To install CLI
* Create Python venv (_Python 3.x_ required; from `IoT-Cloud` directory):<br>
    `python3 -m venv venv`
* Activate venv: <br>
    `source ./venv/bin/activate`
* install CLI (from `IoT-Cloud` directory): `pip install --editable .`
* Test if it's working: `iot-cloud-cli --help`

Expected output: <br>
```Usage: iot-cloud-cli [OPTIONS] COMMAND [ARGS]...

Options:
  --debug / --no-debug
  -b, --broker TEXT
  -p, --port INTEGER
  --help                Show this message and exit.

Commands:
  device
  user
```

### Example Flows
These are example sequences of commands to show how to perform various tasks using CLI

* Register to Server by accessing `https://localhost/login`
* Set Server `access_token` returned by registration: `export ACCESS_TOKEN=<value>`


* Register to AA by accessing `https://localhost/attr_auth/login`
* Set AA `access_token` returned by registration: `export AA_ACCESS_TOKEN=<value>`


* Set broker URL on `MQTT_BROKER` variable in `./client/cli.py` (or use `-b` option in following commands)

* Register to broker
    * `iot-cloud-cli user register-to-broker <your-password>`
* Initialize per-user global hashing and encryption keys
    * `iot-cloud-cli user init-global-keys`
* Create new device type
    * `iot-cloud-cli user create-device-type <some-description>`
    * _Save the device type ID from response for future use_
    
TODO
