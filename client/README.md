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

 TODO
