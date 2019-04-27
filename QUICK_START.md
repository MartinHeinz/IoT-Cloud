### To start DB:
* `cd IoT-Cloud/postgres`
* `docker network create -d bridge --subnet=172.26.0.0/16 iot-cloud_shared_net`
* `docker-compose pull`
* `CURRENT_UID=$(id -u):$(id -g) docker-compose up`

### To start server:
* `cd IoT-Cloud`
* `docker-compose pull`
* `CURRENT_UID=$(id -u):$(id -g) docker-compose up`

### To start virtual device (node-RED):
* `docker pull martinheinz/iot_cloud_node_red:try-it-out`
* `docker run -it --network host martinheinz/iot_cloud_node_red:try-it-out`
* Open <http://127.0.0.1:1880/> in browser to see device interface (node-RED UI)

### Set device credentials (using node-RED UI):
* Double click on any of the mqtt nodes (pink ones)
* Click pencil Icon to the right of Local MQTT Broker
* Go to Security tab and set credentials to - username: `d:46`, password: `RaspberryPiPass`
* Click _Deploy_ in upper right corner

### To start user CLI:
* `docker pull martinheinz/iot_cloud_cli:try-it-out`
* `docker run -it --network host martinheinz/iot_cloud_cli:try-it-out` - Now you are in console with CLI ready


For information about any part of the framework see [README.md](README.md) and link to other "Readmes" in _Additional information_ section.

### To use prepared users and devices (in user CLI):
* There are 2 users
    * `JohnSmith` - has 2 devices set-up with 2 and 3 actions respectively, 1 scene and all necessary keys
    * `JozkoMrkvicka` - is a authorized user that can use one of the devices of `JohnSmith`
* For both users there are `keystore.json` files in `IoT-Cloud/client/user` directory
    * `keystore.json` for `JohnSmith` - This is used by default.
    * `keystore_other.json` for `JozkoMrkvicka`
* Keystore named `keystore.json` is always used, so to switch between users rename the files back-and-forth
and export their access tokens
* Access tokens and ID for `JohnSmith`:
    * `export ACCESS_TOKEN='eyJhbGciOiJIUzUxMiIsImlhdCI6MTU1NTY2NjEzMSwiZXhwIjo0NzExNDI2MTMxfQ.eyJpZCI6NSwidG9rZW4iOiI1YWJlZDI5MDU0Nzc3YmVmMjllMWZkOGRlNDI5M2RmNDk1OGM1YTBhIn0.yfCax12DQw1EfqxuPdJexEbyX0hJcwmOoLob7jk0FbS7G-ZG-4SEGhT2M9d49US8NmuIYSFJUnpyMsbulfRirA'`
    * `export AA_ACCESS_TOKEN='eyJhbGciOiJIUzUxMiIsImlhdCI6MTU1NTY2NjYzMiwiZXhwIjo0NzExNDI2NjMyfQ.eyJpZCI6NCwidG9rZW4iOiJhZmY5ZGEyZGYwODE4MThjYjI0N2VjKSkifQ.npq_a9Ndiv6r1WGyJuXEjNVdrO1kpKHa0-85hqx5LyAAIXt1g5CbtsgYYG-VUcv47ouOttpopjrWAjzGS_c1-A'`
    * ID: 5
* Access tokens and ID for `JozkoMrkvicka`:
    * `export ACCESS_TOKEN='eyJhbGciOiJIUzUxMiIsImlhdCI6MTU1NTY2NjE5MywiZXhwIjo0NzExNDI2MTkzfQ.eyJpZCI6NiwidG9rZW4iOiI1OTkzODA0NzRkYTk4MDQyZjRiN2I5ZmQ0YTBhYWI0YTZjMzQ2ZTkwIn0.CUQrgChsUHjdxZzD0gWqgu_RUmT2PF-Kvx_i-3eekb02jVlVwVTiwXawp30RUiVaJs-HUiuCbrjJ2httJbxRVA'`
    * `export AA_ACCESS_TOKEN='eyJhbGciOiJIUzUxMiIsImlhdCI6MTU1NTY2NjY1OCwiZXhwIjo0NzExNDI2NjU4fQ.eyJpZCI6NSwidG9rZW4iOiI5M2MzMWNiM2FjMzE5Njk5N2Y0OTAxKSkifQ.BlWbGUa80ycjcG8NyZJZPJEE_hC7-ZE98qdJaeVGeniSxLFnisLQgqynWamXlwFeS9YqYxWprJpkEb3aAMLUrQ'`
    * ID: 6
* Devices (owned by `JohnSmith`):
    * `RaspberryPi` (This one is shared with `JozkoMrkvicka`)
        * ID: `46`
        * Password: `RaspberryPiPass`
        * Actions: `On`, `Off`, `Stat`
        * Data file: `data.json`
    * `Microwave`
        * ID: `47`
        * Password: `Bad-Pass-Again`
        * Actions: `On`, `Off`
        * Data file: `data_microwave.json`
        
    * You can switch between devices by accessing its container and renaming data files in `client/device`
    (file named `data.json` is always used) and changing topics and credentials in _node-RED_ UI

        
* Scene:
    * Name: `TurnOnAndStat`
    * Actions Triggered: `RaspberryPi` - `On`, `Stat`; `Microwave` - `On`
    * _Note: With this quick start you will have only the `RaspberryPi` device running, therefore you will see
    only `On` and `Stat` action being triggered, but you can see in `iot-cloud-mqtt` logs, which show that container is sending 3 messages, not just 2._
    
* Device Type:
    * Both devices are created with same Device Type with id `a946c5fe-073e-440d-84a3-1f1f4a3d482c`
    
    
### Sample commands:
_Important:_ Before using these commands export tokens for user `JohnSmith` from previous section. If you want to use other user,
export their access tokens and switch `keystore.json` as described in previous section.

To see output of messages and actions see _Debug Tab_ in _node-RED_ UI (Click on the Bug Icon in top right corner or press "`ctrl+g d`")

More information about specific commands [client/README.md](client/README.md)

* Trigger action: `iot-cloud-cli user trigger-action 46 RaspberryPi Stat`
* Trigger scene: `iot-cloud-cli user trigger-scene TurnOnAndStat`
* Query data: `iot-cloud-cli user get-device-data 5 46 RaspberryPi`
* Query data by integer range: `iot-cloud-cli user get-device-data-by-num-range 5 46 RaspberryPi --lower 764215`
* Trigger action with other user: `iot-cloud-cli user trigger-action 46 RaspberryPi On --no-owner`
* Query data as non-owner: `iot-cloud-cli user get-device-data 6 46 RaspberryPi --no-owner`
* Trigger fake action: `iot-cloud-cli user trigger-action 46 RaspberryPi On --fake`

### Extending DB data set:
You can add more rows to DB by downloading these files:
* [`populate_data.sql` (link)](http://davinci.fmph.uniba.sk/~heinz4/diplomova_praca/populate_data.sql) for `IoT-Cloud/app/populate_full.sql`
* [`attr_auth_populate_data.sql` (link)](http://davinci.fmph.uniba.sk/~heinz4/diplomova_praca/attr_auth_populate_data.sql) for `IoT-Cloud/app/attr_auth_populate_full.sql`

And appending them to existing files (e.g. `cat <downloaded file> >> populate_full.sql`)

This is just so you can see performance when DB contains much more data (extra ~7500 rows)

### Accessing running container and its data:
If you want to for example, switch users or devices, or to see source code that is inside containers or to see SQL dumps of data inserted:
* `docker ps`
* From output of previous command choose value from `NAMES`
* `docker exec -it <NAME> bash`

