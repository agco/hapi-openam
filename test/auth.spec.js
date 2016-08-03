'use strict';

const Hapi = require('hapi');
const chai = require('chai');
const expect = chai.expect;
const Promise = require('bluebird');
const openAM = require('../index');
const redis = require('redis');
const $http = require('http-as-promised');
const MD5 = require('MD5');
const nock = require('nock');
const basicKey = openAM.basicKey;
const oauth2Key = openAM.oauth2Key;
const port = '5050';
const url = `http://0.0.0.0:${port}`;
const openAMBaseURL = 'https://example.com';
const openAMTokenPath = '/access_token';
const openAMInfoPath = '/tokeninfo';
const openAMUserPath = '/userinfo';
const openAMURL = openAMBaseURL + openAMTokenPath;
const mockToken = 'f6dcf133-f00b-4943-a8d4-ee939fc1bf29';
const openAMMock = nock(openAMBaseURL);
let requestUser;

Promise.promisifyAll(redis.RedisClient.prototype);
Promise.promisifyAll(redis.Multi.prototype);

const redisClient = redis.createClient();

const debug = require('debug')('openam');

chai.should();
let server;

const checkWaitAndVerifyExpired = (hash, wait) => {
  return checkInitial(hash)
    .then(() => {
      return Promise.delay(wait);
    })
    .then(() => {
      return checkExpired(hash);
    });
};

const checkInitial = (hash) => {
  return checkVal(hash).spread(body => {
    return expect(body).to.not.be.null;
  });
};

const checkExpired = (hash) => {
  return checkVal(hash).spread(body => {
    return expect(!body).to.be.true;
  });
};

const checkVal = (hash) => {
  return redisClient
    .multi()
    .get(hash)
    .execAsync();
};

describe('authentication', () => {
  before(done => {
    const basicOptions = {
      openAMBaseURL: openAMURL,
      openAMInfoURL: openAMBaseURL + openAMInfoPath,
      client_id: 'client_id',
      client_secret: 'client_secret',
      redis: {},
      scope: ['sub', 'username', 'email']
    };

    const oauth2Options = {
      openAMInfoURL: openAMBaseURL + openAMInfoPath,
      openAMUserURL: openAMBaseURL + openAMUserPath,
      redis: {}
    };

    server = new Hapi.Server();
    server.connection({ port: 5050 });
    server.register([
      { register: require('inject-then') },
      { register: require('hapi-auth-basic') },
      { register: require('hapi-auth-bearer-token') }
    ], (err) => {
      if (err) {
        throw err;
      }
      server.auth.strategy('simple', 'basic', { validateFunc: openAM.basicStrategyValidate(basicOptions) });
      server.route({
        method: 'GET',
        path: '/simple',
        config: { auth: 'simple' },
        handler: (request, reply) => {
          requestUser = request.auth.credentials;
          return reply('ok');
        }
      });
      server.route({
        method: 'GET', path: '/simple_err', config: { auth: 'simple' }, handler: (request, reply) => {
          debug('handling request');
          return reply(new Error('bad request'));
        }
      });
      server.auth.strategy('oauth2', 'bearer-access-token',
        { validateFunc: openAM.bearerTokenStrategyValidate(oauth2Options) });
      server.route({
        method: 'GET',
        path: '/oauth',
        config: { auth: 'oauth2' },
        handler: (request, reply) => {
          requestUser = request.auth.credentials;
          return reply('ok');
        }
      });
      server.route({
        method: 'GET', path: '/oauth_err', config: { auth: 'oauth2' }, handler: (request, reply) => {
          debug('handling request');
          return reply(new Error('bad request'));
        }
      });
      server.start(done);
    })
  });

  describe('basic auth', () => {

    it('returns  401 for requests without auth headers', () => {
      server.injectThen('/simple')
        .then(response => {
          expect(response.statusCode).to.be.eq(401);
        });
    });

    describe('redis caches authentication', () => {
      const username = 'foo';
      const password = 'bar';
      const token = { sub: '234234' };

      before(() => {
        const header = `${username}:${password}`;
        const hashedHeader = MD5(header);
        return redisClient
          .multi()
          .set(basicKey(hashedHeader), JSON.stringify(token))
          .execAsync();
      });

      it('checks for an existing base64 token to auth', () => {
        const headerString = new Buffer(`${username}:${password}`).toString('base64');
        server.injectThen({ method: 'GET', url: '/simple', headers: { Authorization: `Basic ${headerString}` } })
          .then((response) => {
            expect(response.statusCode).to.be.eq(200);
          });
      });

      it('returns downstream errors as is', () => {
        const headerString = new Buffer(`${username}:${password}`).toString('base64');
        server.injectThen({ method: 'GET', url: '/simple_err', headers: { Authorization: `Basic ${headerString}` } })
          .then((response) => {
            expect(response.statusCode).to.be.eq(500);
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
          .get(openAMInfoPath + '?access_token=' + mockToken)
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
        return server.injectThen({ method: 'GET', url: '/simple', headers: { Authorization: `Basic ${headerString}` } })
      });

      after(() => {
        return redisClient.flushdbAsync();
      });

      it('removes the token', () => {
        return checkWaitAndVerifyExpired(basicKey(hashedToken), 3000);
      });
    });

    describe('openAM check', () => {

      before(() => {
        openAMMock
          .post(openAMTokenPath)
          .reply(200, {
            'expires_in': 599,
            'token_type': 'Bearer',
            'refresh_token': 'f9063e26-3a29-41ec-86de-1d0d68aa85e9',
            'access_token': mockToken
          })
          .get(openAMInfoPath + '?access_token=' + mockToken)
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

      after(() => {
        return redisClient.flushdbAsync();
      });

      it('validates a user if their credentials exist in openAM and returns their token info', () => {
        const user = 'missing';
        const pass = 'missing';

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
          .spread(res => {
            expect(res.statusCode).to.equal(200);
            const header = `${user}:${pass}`;
            const hashedHeader = MD5(header);

            expect(requestUser.sub).to.equal('h234ljb234jkn23');
            expect(requestUser.token.agcoUUID).to.equal('h234ljb234jkn23');
            expect(requestUser.token.username).to.exist;
            expect(requestUser.token.email).to.exist;

            const getHeader = () => {
              return redisClient.getAsync(basicKey(hashedHeader));
            };

            const checkToken = token => {
              const parsedToken = JSON.parse(token);
              expect(parsedToken.token.agcoUUID).to.equal('h234ljb234jkn23');
              expect(parsedToken.sub).to.equal('h234ljb234jkn23');
            };

            return getHeader().then(checkToken);
          });
      });

      it('validates with tokenInfo and cached results', () => {
        const user = 'missing';
        const pass = 'missing';

        const getValidTokenInfo = () => {
          return $http.get(`${url}/simple`, {
            error: false,
            auth: {
              user: user,
              pass: pass
            },
            json: {
              deviceId: true
            }
          });
        };

        const checkResponse = res => {
          expect(res.statusCode).to.equal(200);

          const header = `${user}:${pass}`;
          const hashedHeader = MD5(header);

          expect(requestUser.sub).to.equal('h234ljb234jkn23');
          expect(requestUser.token.agcoUUID).to.equal('h234ljb234jkn23');
          expect(requestUser.token.username).to.exist;
          expect(requestUser.token.email).to.exist;

          const getHeader = () => {
            return redisClient.getAsync(basicKey(hashedHeader));
          };

          const checkToken = token => {
            expect(JSON.parse(token).sub).to.equal('h234ljb234jkn23');
          };

          return getHeader().then(checkToken);
        };

        return getValidTokenInfo()
          .spread(checkResponse);
      });

      it('invalidates a user if openAM token POST returns a 401 code', () => {
        const user = 'invalid';
        const pass = 'invalid';

        return $http
          .get(`${url}/simple`, {
            error: false,
            auth: {
              user: user,
              pass: pass
            },
            json: {
              deviceId: true
            }
          })
          .spread(res => {
            expect(res.statusCode).to.equal(401);
          });
      });
    });

    describe('Error handling check', () => {
      before(() => {
        openAMMock
          .post(openAMTokenPath)
          .reply(200, {
            expires_in: 599,
            token_type: 'Bearer',
            refresh_token: 'f9063e26-3a29-41ec-86de-1d0d68aa85e9',
            access_token: mockToken
          })
          .get(openAMInfoPath + '?access_token=' + mockToken)
          .reply(404, {
            error: 'Not found',
            error_description: 'Could not read token in CTS'
          });
      });

      after(() => {
        return redisClient.flushdbAsync();
      });

      it('invalidates a user if openAM token POST returns a 404 code', () => {
        const user = 'invalid';
        const pass = 'invalid';

        return $http
          .get(`${url}/simple`, {
            error: false,
            auth: {
              user: user,
              pass: pass
            },
            json: {
              deviceId: true
            }
          })
          .spread(res => {
            expect(res.statusCode).to.equal(401);
          });
      });
    });

  });

  describe('OAUTH2', () => {
    it('returns 401 for requests without auth headers', () => {
      return $http
        .get(`${url}/oauth`, { error: false })
        .spread(res => {
          expect(res.statusCode).to.equal(401);
        });

    });

    describe('Redis caches authentication', () => {
      const token = 'qux';
      const tokenHeader = `Bearer ${token}`;
      const expectedName = 'Robot';

      before(() => {
        //create token with info
        const hashedHeader = MD5(token);
        const userInfo = {
          name: expectedName
        };

        return redisClient
          .multi()
          .set(oauth2Key(hashedHeader), JSON.stringify(userInfo))
          .execAsync();
      });

      it('checks for an existing oauth2 token to auth', () => {
        return $http
          .get(`${url}/oauth`, {
            error: false,
            headers: {
              Authorization: tokenHeader
            }
          })
          .spread(res => {
            expect(res.statusCode).to.equal(200);
            expect(requestUser.name).to.equal(expectedName);
          });
      });

    });

    describe('Redis expires tokens with oauth2 strategy ', () => {
      const mockTokenInfo = {
        profile: '',
        mail: 'agc2.dealer.1@agcocorp.com',
        scope: [
          'mail',
          'cn',
          'agcoUUID'
        ],
        grant_type: 'password',
        cn: 'agc2 dealer 1',
        realm: '/dealers',
        token_type: 'Bearer',
        expires_in: 3,
        access_token: mockToken,
        agcoUUID: '3f946638-ea3f-11e4-b02c-1681e6b88ec1'
      };

      before(() => {
        openAMMock
          .get(`${openAMInfoPath}?access_token=${mockToken}`)
          .reply(200, mockTokenInfo);

        return $http
          .get(`${url}/oauth`, {
            error: false,
            headers: {
              Authorization: `Bearer ${mockToken}`
            }
          });
      });

      it('removes the token', () => {
        const hashedToken = MD5(mockToken);
        return checkWaitAndVerifyExpired(oauth2Key(hashedToken), 4000);
      });
    });

    describe('Tokens not in redis are checked against the provided tokeninfo endpoint', () => {
      const mockTokenInfo = {
        profile: '',
        mail: 'agc2.dealer.1@agcocorp.com',
        scope: [
          'mail',
          'cn',
          'profile'
        ],
        grant_type: 'password',
        cn: 'agc2 dealer 1',
        realm: '/dealers',
        token_type: 'Bearer',
        expires_in: 7136,
        access_token: mockToken,
        agcoUUID: '3f946638-ea3f-11e4-b02c-1681e6b88ec1'
      };

      const error = {
        error: 'Not found',
        error_description: 'Could not read token in CTS'
      };

      const badToken = 'foo';

      before(() => {
        openAMMock
          .get(`${openAMInfoPath}?access_token=${mockToken}`)
          .reply(200, mockTokenInfo)
          .get(`${openAMInfoPath}?access_token=${badToken}`)
          .reply(404, error)
          .get(`${openAMInfoPath}?access_token=${badToken}`)
          .reply(200, mockTokenInfo);
      });

      beforeEach(() => {
        return redisClient.flushallAsync();
      });

      it('Has the user info on the req body if it is found and stores it in redis', () => {
        return $http
          .get(`${url}/oauth`, {
            error: false,
            headers: {
              Authorization: `Bearer ${mockToken}`
            }
          })
          .spread(res => {
            const hashedToken = MD5(mockToken);

            expect(res.statusCode).to.equal(200);
            expect(requestUser.sub).to.equal(mockTokenInfo.agcoUUID);

            return redisClient
              .multi()
              .get(oauth2Key(hashedToken))
              .execAsync()
              .spread(body => {
                return expect(JSON.parse(body).sub).to.equal(mockTokenInfo.agcoUUID);
              });
          });
      });

      it('invalidates a user if oauth returns 401', () => {
        return $http
          .get(`${url}/oauth`, {
            error: false,
            headers: {
              Authorization: 'Bearer foo'
            }
          })
          .spread(res => {
            expect(res.statusCode).to.equal(401);
            const hashedToken = MD5(badToken);

            return redisClient
              .multi()
              .get(oauth2Key(hashedToken))
              .execAsync().spread(body => {
                return expect(body).to.equal(null);
              });
          });
      });

      it('returns downstream errors as is', () => {
        return $http
          .get(`${url}/oauth_err`, {
            error: false,
            headers: {
              Authorization: 'Bearer foo'
            }
          })
          .spread(res => {
            expect(res.statusCode).to.equal(500);
          });
      });
    });
  });
});
