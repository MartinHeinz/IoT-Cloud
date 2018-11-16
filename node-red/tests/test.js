// Run using npm test (mocha needs to be installed globally)

const should = require('should');
const RED = require('node-red');
const express = require("express");
const http = require('http');

const app = express();
const server = http.createServer(app);
const settings = {
    httpAdminRoot:"/red",
    httpNodeRoot: "/api",
    userDir:"../",
    flowFile: "../flow.json",
    functionGlobalContext: { }    // enables global context
};


describe('Node-RED', function() {

    before(function() {
		RED.init(server, settings);
		return RED.start();
    });

    after(function() {
        RED.stop();
    });


    describe('Device', function () {
        it('parses payload', function (done) {
			let process = RED.nodes.getNode("1ac6d612.d7152a");
			let json_node = RED.nodes.getNode("51b1392c.c4b6c8");

			json_node.on("input", function (msg) {
				should(msg.payload).have.property("setOn", "True");
				done();
			});
			process.receive({ payload: "Wi4HsSVQY0EQ/RuRC7winks= X3hxxWCG+926QW2ZGuIi0Q==" });
		});
	});
});

// TODO change to node-RED testing lib - https://github.com/node-red/node-red/wiki/Testing , https://github.com/node-red/node-red-node-test-helper