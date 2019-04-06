## Node-RED (Device CLI)

This is directory that contains flow and settings used to create _node-RED_ device.

### Prerequisites
* _npm_
* _node-RED_ (to install follow steps at <https://nodered.org/docs/getting-started/installation>)

### Running
To start _node-RED_ with prepared `settings.js` file
* if _node-RED_ is installed in `node_modules`, then run: <br/> `./node_modules/node-red/bin/node-red-pi -s ./settings.js`
* if installed globally use `node-red -s ./settings.js`


### Usage
* After running, you can open browser flow editor at <http://127.0.0.1:1880/>
* You will want to configure MQTT Broker and device credentials:
    * double click on any of the _mqtt_ nodes (pink ones)
    * Click pencil Icon to the right of _Local MQTT Broker_
    * Set _Server_ field to IP address of MQTT broker you are trying to connect to (see _IoT-Cloud_ app `config.env`)
    * Next click Pencil Icon to the right of _TLS Configuration_ and provide _Certificate_ and _CA Certificate_.
        These should be the certs in `mosquitto/certs/server/server.crt` and `mosquitto/certs/ca/ca.crt` respectively
    * Next go to _Security_ tab in broker settings and provide credentials to your previously registered device
    * Lastly click on each of the _mqtt_ nodes (pink ones) and change `d:<id>` to ID of your device
    * Click _Update_ and _Deploy_ (top right)

* At this point you should see message like this in console from which you ran _node-RED_: <br/> `24 Mar 12:58:23 - [info] [mqtt-broker:Local MQTT Broker] Connected to broker: mqtts://172.26.0.8:8883`
* To see all debugging messages you can view console
* To see triggered actions in browser click on Bug Icon up top right corner to display debug tab.
* You can send data to server by clicking _send_save_data_ Inject node
* You can send/remove data to/from server by clicking _send_add_fake_tuple_ Inject node and _send_remove_fake_tuple_ respectively.
