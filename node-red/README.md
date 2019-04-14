## Node-RED (Device CLI)

This is directory that contains flow and settings used to create _node-RED_ device.

### Prerequisites
* _Docker_

For running on host:

* _npm_
* _node-RED_ (to install follow steps at <https://nodered.org/docs/getting-started/installation>)
- _Python 3.x_
- _PBC_ (Please see [_Running tests section_ in main README](../README.md))
- _Charm-Crypto_ (Please see [_Running tests section_ in main README](../README.md))


### Running using Docker (recommended)
* `docker pull martinheinz/iot_cloud_node_red:latest`
* `docker run -it --network host martinheinz/iot_cloud_node_red`

### Running on host
To start _node-RED_ with prepared `settings.js` file
* if you installed _PBC_ just now (or have not logged out since) please log out and log back in, to export `LD_LIBRARY_PATH`
globally (exporting it in one terminal session is not enough for _node-RED_)
* if _node-RED_ is installed in `node_modules`, then run: <br/> `./node_modules/node-red/bin/node-red-pi -s ./settings.js`
* if installed globally use `node-red -s ./settings.js`


### Usage
* After running, you can open browser flow editor at <http://127.0.0.1:1880/>
* You will want to configure MQTT Broker and device credentials:
    * double click on any of the _mqtt_ nodes (pink ones)
    * Click pencil Icon to the right of _Local MQTT Broker_
    * Set _Server_ field to IP address of MQTT broker you are trying to connect to (see _IoT-Cloud_ app `config.env`)
    * _Optional step (Only if `require_certificate true` is set in `mosquitto.conf`):_ click Pencil Icon to the right of _TLS Configuration_ and provide _Certificate_ and _CA Certificate_.
        These should be the certs in `mosquitto/certs/server/server.crt` and `mosquitto/certs/ca/ca.crt` respectively
    * Next go to _Security_ tab in broker settings and provide credentials to your previously registered device
    * Lastly click on each of the _mqtt_ nodes (pink ones) and change `d:<id>` to ID of your device
    * Click _Update_ and _Deploy_ (top right)

* At this point you should see message like this in console from which you ran _node-RED_: <br/> `24 Mar 12:58:23 - [info] [mqtt-broker:Local MQTT Broker] Connected to broker: mqtts://172.26.0.8:8883`
* To see all debugging messages you can view console
* To see triggered actions in browser click on Bug Icon up top right corner to display debug tab.
* You can send data to server by clicking _send_save_data_ Inject node
* You can send/remove data to/from server by clicking _send_add_fake_tuple_ Inject node and _send_remove_fake_tuple_ respectively.
