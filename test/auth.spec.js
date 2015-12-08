'use strict';
const Hapi = require('hapi');
const chai = require('chai');

chai.should();
let server;

describe('authentication', () => {
    before((done) => {
        server = new Hapi.Server();
        server.connection({ port: 5000});
        server.register([{register: require('inject-then')}], () => {
            server.start(done);
        })
    });

    describe('basic auth', () => {
        it('returns  401 for requests without auth headers', () => {

        });
    });


});