'use strict';

const Hapi = require('hapi');
const chai = require('chai');
const expect = chai.expect;
const Promise = require('bluebird');
const openAM = require('../index');
const redis = require('then-redis');
const db = redis.createClient();
const $http = require('http-as-promised')
const MD5 = require('MD5');
const nock = require('nock');
const basicKey = openAM.basicKey;
const oauth2Key = openAM.oauth2Key;
const port = '5050';
const url = 'http://0.0.0.0:'+port;
const openAMBaseURL = 'https://example.com';
const openAMTokenPath = '/access_token';
const openAMInfoPath = '/tokeninfo';
const openAMUserPath = '/userinfo';
const openAMURL = openAMBaseURL + openAMTokenPath;
const mockToken = 'f6dcf133-f00b-4943-a8d4-ee939fc1bf29';
const openAMMock = nock(openAMBaseURL);
let requestUser;

const debug = require('debug')('openam');

chai.should();
let server;

const checkWaitAndVerifyExpired = (hash, wait) => {
  return checkInitial(hash)
    .then(function () {
        return Promise.delay(wait);
    })
    .then(function() {
        return checkExpired(hash);
    });
}

const checkInitial = (hash) => {
  return checkVal(hash).spread(function (body) {
      return expect(body).to.not.be.null;
  });
}

const checkExpired = (hash) => {
  return checkVal(hash).spread(function (body) {
      return expect(!body).to.be.true;
  });
}

const checkVal= (hash) => {
  db.multi();
  db.get(hash);
  return db.exec();
}

const setVal = (key, obj) => {
  db.multi();
  db.set(key, JSON.stringify(obj));
  return db.exec();
}

describe('authentication', () => {
  before((done) => {
    const basicOptions = {
      openAMBaseURL: openAMURL,
      openAMInfoURL: openAMBaseURL + openAMInfoPath,
      client_id: 'client_id',
      client_secret: 'client_secret',
      redis: {},
      scope: ['sub', 'username', 'email']
    }

    const oauth2Options = {
      openAMInfoURL: openAMBaseURL + openAMInfoPath,
      openAMUserURL: openAMBaseURL + openAMUserPath,
      redis: {}
    };

    server = new Hapi.Server();
    server.connection({ port: 5050});
    server.register([
      {register: require('inject-then')},
      {register: require('hapi-auth-basic')},
      {register: require('hapi-auth-bearer-token')}
    ], (err) => {
        if(err) throw err;
        server.auth.strategy('simple', 'basic', { validateFunc: openAM.basicStrategyValidate(basicOptions) });
        server.route({ method: 'GET', path: '/simple', config: { auth: 'simple' }, handler: function (request, reply) { requestUser = request.auth.credentials; return reply('ok'); } });
        server.route({ method: 'GET', path: '/simple_err', config: { auth: 'simple' }, handler: function (request, reply) {
          debug('handling request');
          return reply(new Error('bad request')); }
        });
        server.auth.strategy('oauth2', 'bearer-access-token', { validateFunc: openAM.bearerTokenStrategyValidate(oauth2Options) });
        server.route({ method: 'GET', path: '/oauth', config: { auth: 'oauth2' }, handler: function (request, reply) { requestUser = request.auth.credentials; return reply('ok'); } });
        server.route({ method: 'GET', path: '/oauth_err', config: { auth: 'oauth2' }, handler: function (request, reply) {
          debug('handling request');
          return reply(new Error('bad request')); }
        });
        server.start(done);
    })
  });

  describe('basic auth', () => {

    it('returns  401 for requests without auth headers', () => {
      server.injectThen('/simple')
        .then(function (response) {
          (response.statusCode).should.equal(401);
        });
    });

    describe('redis caches authentication', () => {
      const username = 'foo';
      const password = 'bar';
      const token = {sub: '234234'};

      before(function() {
        var header = username + ':' + password;
        var hashedHeader = MD5(header);
        db.multi();
        db.set(basicKey(hashedHeader), JSON.stringify(token));
        return db.exec();
      });

      it('checks for an existing base64 token to auth', () => {
        const headerString = new Buffer(`${username}:${password}`).toString('base64');
        server.injectThen({method: 'GET', url: '/simple', headers: {Authorization: `Basic ${headerString}`}})
          .then((response) => {
            (response.statusCode).should.equal(200);
          });
      });

      it('returns downstream errors as is', () => {
        const headerString = new Buffer(`${username}:${password}`).toString('base64');
        server.injectThen({method: 'GET', url: '/simple_err', headers: {Authorization: `Basic ${headerString}`}})
          .then((response) => {
            (response.statusCode).should.equal(500);
          });
      });

    });

    describe('redis expires tokens with basic strategy', () => {
      const username = 'missing';
      const password = 'missing';
      const hashedToken = MD5(username + ':' + password);

      before(() => {
        openAMMock
          .post(openAMTokenPath)
          .reply(200, {
              'expires_in': 2,
              'token_type': 'Bearer',
              'refresh_token': 'f9063e26-3a29-41ec-86de-1d0d68aa85e9',
              'access_token': mockToken
          })
          .get(openAMInfoPath+'?access_token='+mockToken)
          .reply(200, {
              'agcoUUID': 'h234ljb234jkn23',
              'scope': [
                  'agcoUUID',
                  'username',
                  'email'
              ],
              'username': 'demo',
              'email': 'foo@bar.com'
          });

        const headerString = new Buffer(`${username}:${password}`).toString('base64');
        return server.injectThen({method: 'GET', url: '/simple', headers: {Authorization: `Basic ${headerString}`}})
      });

      after(function() {
        return db.flushdb();
      });

      it('removes the token', function() {
        this.timeout(5000);
        return checkWaitAndVerifyExpired(basicKey(hashedToken), 3000);
      });
    });

    describe('openAM check', function() {

        before(function() {
            openAMMock
                .post(openAMTokenPath)
                .reply(200, {
                    'expires_in': 599,
                    'token_type': 'Bearer',
                    'refresh_token': 'f9063e26-3a29-41ec-86de-1d0d68aa85e9',
                    'access_token': mockToken
                })
                .get(openAMInfoPath+'?access_token='+mockToken)
                .reply(200, {
                    'agcoUUID': 'h234ljb234jkn23',
                    'scope': [
                        'agcoUUID',
                        'username',
                        'email'
                    ],
                    'username': 'demo',
                    'email': 'foo@bar.com'
                })
                .post(openAMTokenPath)
                .reply(400);
        });

        after(function() {
            return db.flushdb();
        });

        it('validates a user if their credentials exist in openAM and returns '+
            'their token info', function() {
            var user = 'missing',
                pass = 'missing';

            return $http.get(url + '/simple', {
                error: false,
                auth: {
                    user: user,
                    pass: pass
                },
                json: {
                    deviceId: true
                }
            })
            .spread(function checkResponse(res, body) {
                expect(res.statusCode).to.equal(200);

                var header = user + ':' + pass,
                hashedHeader = MD5(header);

                expect(requestUser.sub).to.equal('h234ljb234jkn23');
                expect(requestUser.token.agcoUUID).to.equal('h234ljb234jkn23');
                expect(requestUser.token.username).to.exist;
                expect(requestUser.token.email).to.exist;

                return getHeader().then(checkToken);

                function getHeader() {
                    return db.get(basicKey(hashedHeader));
                }

                function checkToken(token) {
                    var parsedToken = JSON.parse(token);

                    expect(parsedToken.token.agcoUUID).to.equal('h234ljb234jkn23');
                    expect(parsedToken.sub).to.equal('h234ljb234jkn23');
                }

            });
        });

        it('validates with tokenInfo and cached results', function() {
            var user = 'missing',
                pass = 'missing';

            return getValidTokenInfo()
                .spread(checkResponse);

            function getValidTokenInfo() {
                return $http.get(url + '/simple', {
                    error: false,
                    auth: {
                        user: user,
                        pass: pass
                    },
                    json: {
                        deviceId: true
                    }
                });
            }

            function checkResponse(res) {
                expect(res.statusCode).to.equal(200);

                var header = user + ':' + pass,
                    hashedHeader = MD5(header);

                expect(requestUser.sub).to.equal('h234ljb234jkn23');
                expect(requestUser.token.agcoUUID).to.equal('h234ljb234jkn23');
                expect(requestUser.token.username).to.exist;
                expect(requestUser.token.email).to.exist;

                return getHeader().then(checkToken);

                function getHeader() {
                    return db.get(basicKey(hashedHeader));
                }

                function checkToken(token) {
                    expect(JSON.parse(token).sub).to.equal('h234ljb234jkn23');
                }

            }
        });

        it('invalidates a user if openAM token POST returns a 401 code', function() {
            var user = 'invalid',
                pass = 'invalid';

            return $http.get(url + '/simple', {
                error: false,
                auth: {
                    user: user,
                    pass: pass
                },
                json: {
                    deviceId: true
                }
            })
            .spread(function(res, body) {
                expect(res.statusCode).to.equal(401);
            });
        });
    });

    describe('Error handling check', function() {
        before(function() {
            openAMMock
                .post(openAMTokenPath)
                .reply(200, {
                    'expires_in': 599,
                    'token_type': 'Bearer',
                    'refresh_token': 'f9063e26-3a29-41ec-86de-1d0d68aa85e9',
                    'access_token': mockToken
                })
                .get(openAMInfoPath+'?access_token='+mockToken)
                .reply(404, {
                    'error': 'Not found',
                    'error_description': 'Could not read token in CTS'
                });
        });

        after(function() {
            return db.flushdb();
        });

        it('invalidates a user if openAM token POST returns a 404 code', function() {
            var user = 'invalid',
                pass = 'invalid';

            return $http.get(url + '/simple', {
                error: false,
                auth: {
                    user: user,
                    pass: pass
                },
                json: {
                    deviceId: true
                }
            })
            .spread(function(res, body) {
                expect(res.statusCode).to.equal(401);
            });
        });
    });

  });

  describe('OAUTH2', function() {

    it('returns 401 for requests without auth headers', function() {

        return $http.get(url + '/oauth', {error: false})
            .spread(function(res) {
                expect(res.statusCode).to.equal(401);
            });

    });

    describe('Redis caches authentication', function() {
        var token = 'qux',
            tokenHeader = 'Bearer ' + token,
            expectedName = 'Robot';

        before(function() {
            //create token with info

            var hashedHeader = MD5(token),
                userInfo = {
                    name: expectedName
                };

            db.multi();
            db.set(oauth2Key(hashedHeader), JSON.stringify(userInfo));
            return db.exec();
        });

        it('checks for an existing oauth2 token to auth', function() {
            return $http.get(url + '/oauth', {
                error: false,
                headers: {
                    Authorization: tokenHeader
                }
            })
                .spread(function(res, body) {
                    expect(res.statusCode).to.equal(200);
                    expect(requestUser.name).to.equal(expectedName);
                });
        });

    });

    describe('Redis expires tokens with oauth2 strategy ', function() {

        var mockTokenInfo = {
                'profile': '',
                'mail': 'agc2.dealer.1@agcocorp.com',
                'scope': [
                    'mail',
                    'cn',
                    'agcoUUID'
                ],
                'grant_type': 'password',
                'cn': 'agc2 dealer 1',
                'realm': '/dealers',
                'token_type': 'Bearer',
                'expires_in': 3,
                'access_token': mockToken,
                'agcoUUID': '3f946638-ea3f-11e4-b02c-1681e6b88ec1'
            };

        before(function() {
            openAMMock
                .get(openAMInfoPath+'?access_token='+mockToken)
                .reply(200, mockTokenInfo);

            return $http.get(url + '/oauth', {
                error: false,
                headers: {
                    Authorization: 'Bearer ' + mockToken
                }
            });
        });

        it('removes the token', function() {
            var hashedToken = MD5(mockToken);

            this.timeout(5000);
            return checkWaitAndVerifyExpired(oauth2Key(hashedToken), 4000);
        });
    });

    describe('Tokens not in redis are checked against the provided tokeninfo '+
             'endpoint', function() {
        var mockTokenInfo = {
                'profile': '',
                'mail': 'agc2.dealer.1@agcocorp.com',
                'scope': [
                    'mail',
                    'cn',
                    'profile'
                ],
                'grant_type': 'password',
                'cn': 'agc2 dealer 1',
                'realm': '/dealers',
                'token_type': 'Bearer',
                'expires_in': 7136,
                'access_token': mockToken,
                'agcoUUID': '3f946638-ea3f-11e4-b02c-1681e6b88ec1'
            },
            error = {
                'error': 'Not found',
                'error_description': 'Could not read token in CTS'
            },
            badToken = 'foo';

        before(function() {
            openAMMock
                .get(openAMInfoPath+'?access_token='+mockToken)
                .reply(200, mockTokenInfo)
                .get(openAMInfoPath+'?access_token='+badToken)
                .reply(404, error)
                .get(openAMInfoPath+'?access_token='+badToken)
                .reply(200, mockTokenInfo);
        });

        beforeEach(function() {
            return db.flushall();
        });

        it('Has the user info on the req body if it is found and stores it in '+
            'redis', function() {


            return $http.get(url + '/oauth', {
                error: false,
                headers: {
                    Authorization: 'Bearer ' + mockToken
                }
            })
            .spread(function(res, body) {
                var hashedToken = MD5(mockToken);

                expect(res.statusCode).to.equal(200);
                //expect(requestUser.token.mail).to.equal(mockTokenInfo.mail);
                expect(requestUser.sub).to.equal(mockTokenInfo.agcoUUID);

                db.multi();
                db.get(oauth2Key(hashedToken));
                return db.exec().spread(function(body) {
                    return expect(JSON.parse(body).sub).to.equal(mockTokenInfo.agcoUUID);
                });
            });
        });

        it('invalidates a user if oauth returns 401', function() {
            return $http.get(url + '/oauth', {
                error: false,
                headers: {
                    Authorization: 'Bearer ' + 'foo'
                }
            })
                .spread(function(res, body) {
                    expect(res.statusCode).to.equal(401);
                    var hashedToken = MD5(badToken);

                    db.multi();
                    db.get(oauth2Key(hashedToken));
                    return db.exec().spread(function(body) {
                        return expect(body).to.equal(null);
                    });
                });
        });

        it('returns downstream errors as is', function() {
            return $http.get(url + '/oauth_err', {
                error: false,
                headers: {
                    Authorization: 'Bearer ' + 'foo'
                }
            })
                .spread(function(res, body) {
                    expect(res.statusCode).to.equal(500);
                });
        });
    });
  });
});
