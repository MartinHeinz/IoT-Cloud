### To start DB:
* `cd IoT-Cloud/postgres`
* `docker network create -d bridge --subnet=172.26.0.0/16 iot-cloud_shared_net`
* `docker-compose pull`

### To start server:
* `cd IoT-Cloud`
* `docker-compose pull`

### To start virtual device (node-RED):
* `docker pull martinheinz/iot_cloud_node_red:try-it-out`
* `docker run -it --network host martinheinz/iot_cloud_node_red:try-it-out`
* Open <http://127.0.0.1:1880/> in browser to see device interface

### To start user CLI:
* `docker pull martinheinz/iot_cloud_cli:try-it-out`
* `docker run -it --network host martinheinz/iot_cloud_cli:try-it-out` - Now you are in console with CLI ready


### To use prepared users and devices (in user CLI):
* There are 2 users
    * `JohnSmith` - has 2 devices set-up with 2 and 3 actions respectively, 1 scene and all necessary keys
    * `JozkoMrkvicka` - is a authorized user that can use one of the devices of `JohnSmith`
* For both users there are `keystore.json` files in `IoT-Cloud/client/user` directory
    * `keystore.json` for `JohnSmith` - This is used by default.
    * `keystore_other.json` for `JozkoMrkvicka`
* Keystore named `keystore.json` is always used, so to switch between users rename the files back-and-forth
and export their access tokens
* Access tokens for `JohnSmith`:
    * `export ACCESS_TOKEN='eyJhbGciOiJIUzUxMiIsImlhdCI6MTU1NTY2NjEzMSwiZXhwIjo0NzExNDI2MTMxfQ.eyJpZCI6NSwidG9rZW4iOiI1YWJlZDI5MDU0Nzc3YmVmMjllMWZkOGRlNDI5M2RmNDk1OGM1YTBhIn0.yfCax12DQw1EfqxuPdJexEbyX0hJcwmOoLob7jk0FbS7G-ZG-4SEGhT2M9d49US8NmuIYSFJUnpyMsbulfRirA'`
    * `export AA_ACCESS_TOKEN='eyJhbGciOiJIUzUxMiIsImlhdCI6MTU1NTY2NjYzMiwiZXhwIjo0NzExNDI2NjMyfQ.eyJpZCI6NCwidG9rZW4iOiJhZmY5ZGEyZGYwODE4MThjYjI0N2VjKSkifQ.npq_a9Ndiv6r1WGyJuXEjNVdrO1kpKHa0-85hqx5LyAAIXt1g5CbtsgYYG-VUcv47ouOttpopjrWAjzGS_c1-A'`
* Access tokens for `JozkoMrkvicka`:
    * `export ACCESS_TOKEN='eyJhbGciOiJIUzUxMiIsImlhdCI6MTU1NTY2NjE5MywiZXhwIjo0NzExNDI2MTkzfQ.eyJpZCI6NiwidG9rZW4iOiI1OTkzODA0NzRkYTk4MDQyZjRiN2I5ZmQ0YTBhYWI0YTZjMzQ2ZTkwIn0.CUQrgChsUHjdxZzD0gWqgu_RUmT2PF-Kvx_i-3eekb02jVlVwVTiwXawp30RUiVaJs-HUiuCbrjJ2httJbxRVA'`
    * `export AA_ACCESS_TOKEN='eyJhbGciOiJIUzUxMiIsImlhdCI6MTU1NTY2NjY1OCwiZXhwIjo0NzExNDI2NjU4fQ.eyJpZCI6NSwidG9rZW4iOiI5M2MzMWNiM2FjMzE5Njk5N2Y0OTAxKSkifQ.BlWbGUa80ycjcG8NyZJZPJEE_hC7-ZE98qdJaeVGeniSxLFnisLQgqynWamXlwFeS9YqYxWprJpkEb3aAMLUrQ'`
    
* Devices (owned by `JohnSmith`):
    * `RaspberryPi` (This one is shared with `JozkoMrkvicka`)
        * ID: TODO
        * Actions: `On`, `Off`, `Stat`
    * `Microwave`
        * ID: TODO
        * Actions: `On`, `Off`
        
* Scene:
    * Name: `TurnOnAndStat`
    * Actions Triggered: `RaspberryPi` - `On`, `Stat`; `Microwave` - `On`
    * _Note: With this quick start you will have only the `RaspberryPi` device running, therefore you will see
    only `On` and `Stat`, but you can see in `iot-cloud-mqtt` logs, that container is sending 3 messages, not just 2._
    
* Device Type:
    * Both devices are created with same Device Type with id `` TODO
    
    
### Sample commands: TODO
* Trigger action:
* Trigger scene:
* Query data:
* Query data by integer range:
* Query data as non-owner:
* Trigger fake action:
* Schedule fake action:

### Extending DB data set:
You can add more rows to DB by downloading these files:
* for `populate_full.sql` - <TODO>
* for `attr_auth_populate_full.sql`- <TODO>

And appending them to existing files (e.g. `<downloaded file> >> populate_full.sql`)

This is just so you can see performance when of application, when DB contains much more data (extra ~7500 rows)

### Accessing data inside running containers
If you want to see for example source code that is inside containers or to see SQL dumps of data inserted:
* `docker ps`
* From output of previous command choose value from `NAMES`
* `docker exec -it <NAME> bash`

