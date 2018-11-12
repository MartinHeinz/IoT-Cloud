// Run using npm test (mocha needs to be installed globally)

const assert = require('assert');
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

    describe('Basic test', function () {
        it('starts...', function (done) {
			console.log(RED.nodes.getFlows());
        	done();
		})
	});
});

// TODO: test - load existing flow; in "beforeEach" add nodes that inject some data into existing flow or make http request; check output of flow
