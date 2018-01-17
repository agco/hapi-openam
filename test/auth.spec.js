const Hapi = require('hapi');
const hapiAuthBasic = require('hapi-auth-basic');
const hapiTokenAuth = require('hapi-auth-bearer-token');
const { expect } = require('chai');
const Promise = require('bluebird');
const redis = require('redis');
const MD5 = require('MD5');
const nock = require('nock');
const openAM = require('../index');

const openAMBaseURL = 'https://openam';
const openAMTokenPath = '/access_token';
const openAMInfoPath = '/tokeninfo';
const openAMUserPath = '/userinfo';
const openAMURL = openAMBaseURL + openAMTokenPath;

const openAMMock = nock(openAMBaseURL);
let requestUser;
let server;

Promise.promisifyAll(redis.RedisClient.prototype);
Promise.promisifyAll(redis.Multi.prototype);

const redisClient = redis.createClient();
const flushCache = () => redisClient.flushallAsync();

describe('authentication', () => {
  const mockToken = 'f6dcf133-f00b-4943-a8d4-ee939fc1bf29';
  const agcoUuid = 'fc31efbd-5422-43db-b0f5-61799ceeee56';

  before(async () => {
    nock.disableNetConnect();
    const basicOptions = {
      openAMBaseURL: openAMURL,
      openAMInfoURL: openAMBaseURL + openAMInfoPath,
      client_id: 'client_id',
      client_secret: 'client_secret',
      scope: ['sub', 'username', 'email']
    };

    const oauth2Options = {
      openAMInfoURL: openAMBaseURL + openAMInfoPath,
      openAMUserURL: openAMBaseURL + openAMUserPath
    };

    server = Hapi.server();
    await server.register([hapiAuthBasic, hapiTokenAuth]);
    server.auth.strategy('simple', 'basic', { validate: openAM(basicOptions).basicStrategyValidate });
    server.route({
      method: 'GET',
      path: '/simple',
      config: { auth: 'simple' },
      handler: async (request) => {
        requestUser = request.auth.credentials;
        return 'ok';
      }
    });

    server.route({
      method: 'GET',
      path: '/simple_err',
      config: { auth: 'simple' },
      handler: async () => new Error('bad request')
    });

    server.auth
      .strategy('oauth2', 'bearer-access-token', { validate: openAM(oauth2Options).bearerTokenStrategyValidate });

    server.route({
      method: 'GET',
      path: '/oauth',
      config: { auth: 'oauth2' },
      handler: async (request) => {
        requestUser = request.auth.credentials;
        return 'ok';
      }
    });

    server.route({
      method: 'GET',
      path: '/oauth_err',
      config: { auth: 'oauth2' },
      handler: async () => new Error('bad request')
    });
  });

  describe('basic auth', () => {
    it('returns  401 for requests without auth headers', async () => {
      const response = await server.inject('/simple');
      expect(response.statusCode).to.be.eq(401);
    });

    describe('redis caches authentication', () => {
      const username = 'foo';
      const password = 'bar';
      const token = { sub: '234234' };

      before(async () => {
        const header = `${username}:${password}`;
        const hashedHeader = MD5(header);
        await flushCache();
        await redisClient.setAsync(`openam:${hashedHeader}`, JSON.stringify(token));
      });

      it('checks for an existing base64 token to auth', async () => {
        const headerString = Buffer.from(`${username}:${password}`).toString('base64');
        const response = await server
          .inject({ method: 'GET', url: '/simple', headers: { Authorization: `Basic ${headerString}` } });
        expect(response.statusCode).to.be.eq(200);
        expect(requestUser.sub).to.be.eq('234234');
      });

      it('returns downstream errors as is', async () => {
        const headerString = Buffer.from(`${username}:${password}`).toString('base64');
        const response = await server
          .inject({ method: 'GET', url: '/simple_err', headers: { Authorization: `Basic ${headerString}` } });
        expect(response.statusCode).to.be.eq(500);
      });
    });

    describe('redis expires tokens with basic strategy', () => {
      const username = 'username';
      const password = 'password';
      const hashedToken = MD5(`${username}:${password}`);

      before(async () => {
        await flushCache();
        openAMMock
          .post(openAMTokenPath)
          .reply(200, {
            token_type: 'Bearer',
            refresh_token: 'f9063e26-3a29-41ec-86de-1d0d68aa85e9',
            access_token: mockToken
          })
          .get(`${openAMInfoPath}?access_token=${mockToken}`)
          .reply(200, {
            agcoUUID: agcoUuid,
            scope: ['agcoUUID', 'username', 'email'],
            username: 'demo',
            email: 'foo@bar.com',
            expires_in: 2
          });

        const headerString = Buffer.from(`${username}:${password}`).toString('base64');
        return server.inject({ method: 'GET', url: '/simple', headers: { Authorization: `Basic ${headerString}` } });
      });

      it('expires the cached token', async () => {
        const token = await redisClient.getAsync(`openam:${hashedToken}`);
        expect(token).to.not.be.eq(null);
        await Promise.delay(4000);
        const noToken = await redisClient.getAsync(`openam:${hashedToken}`);
        expect(noToken).to.be.eq(null);
      });
    });

    describe('openAM check', () => {
      describe('valid user', () => {
        before(async () => {
          await flushCache();
          openAMMock
            .post(openAMTokenPath)
            .reply(200, {
              token_type: 'Bearer',
              refresh_token: 'f9063e26-3a29-41ec-86de-1d0d68aa85e9',
              access_token: mockToken
            })
            .get(`${openAMInfoPath}?access_token=${mockToken}`)
            .reply(200, {
              agcoUUID: agcoUuid,
              scope: ['agcoUUID', 'username', 'email'],
              username: 'demo',
              email: 'foo@bar.com',
              expires_in: 599
            });
        });

        it('validates a user if their credentials exist in openAM and returns their token info', async () => {
          const user = 'user';
          const pass = 'pass';
          const hashedHeader = MD5(`${user}:${pass}`);
          const headerString = Buffer.from(`${user}:${pass}`).toString('base64');
          const response = await server
            .inject({ method: 'GET', url: '/simple', headers: { Authorization: `Basic ${headerString}` } });

          expect(response.statusCode).to.be.eq(200);
          expect(requestUser.sub).to.equal(agcoUuid);
          expect(requestUser.token.agcoUUID).to.equal(agcoUuid);
          expect(requestUser.token.username).to.exist();
          expect(requestUser.token.email).to.exist();

          const token = await redisClient.getAsync(`openam:${hashedHeader}`);
          const parsedToken = JSON.parse(token);
          expect(parsedToken.token.agcoUUID).to.equal(agcoUuid);
          expect(parsedToken.sub).to.equal(agcoUuid);
        });

        it('validates with tokenInfo from cached results', async () => {
          const user = 'user';
          const pass = 'pass';
          const hashedHeader = MD5(`${user}:${pass}`);
          const headerString = Buffer.from(`${user}:${pass}`).toString('base64');
          const response = await server
            .inject({ method: 'GET', url: '/simple', headers: { Authorization: `Basic ${headerString}` } });

          expect(response.statusCode).to.be.eq(200);
          expect(requestUser.sub).to.equal(agcoUuid);
          expect(requestUser.token.agcoUUID).to.equal(agcoUuid);
          expect(requestUser.token.username).to.exist();
          expect(requestUser.token.email).to.exist();

          const token = await redisClient.getAsync(`openam:${hashedHeader}`);
          const parsedToken = JSON.parse(token);
          expect(parsedToken.token.agcoUUID).to.equal(agcoUuid);
          expect(parsedToken.sub).to.equal(agcoUuid);
        });
      });

      describe('invalid user', () => {
        before(async () => {
          await flushCache();
          openAMMock
            .post(openAMTokenPath)
            .reply(400);
        });

        it('invalidates a user if openAM token POST returns a 401 code', async () => {
          const user = 'user';
          const pass = 'pass';
          const headerString = Buffer.from(`${user}:${pass}`).toString('base64');
          await flushCache();
          const response = await server
            .inject({ method: 'GET', url: '/simple', headers: { Authorization: `Basic ${headerString}` } });
          expect(response.statusCode).to.equal(401);
        });
      });

      describe('Error handling check', () => {
        before(() => {
          openAMMock
            .post(openAMTokenPath)
            .reply(200, {
              token_type: 'Bearer',
              refresh_token: 'f9063e26-3a29-41ec-86de-1d0d68aa85e9',
              access_token: mockToken
            })
            .get(`${openAMInfoPath}?access_token=${mockToken}`)
            .reply(404);
        });

        it('invalidates a user if openAM token POST returns a 404 code', async () => {
          const user = 'user';
          const pass = 'pass';
          const headerString = Buffer.from(`${user}:${pass}`).toString('base64');
          await flushCache();
          const response = await server
            .inject({ method: 'GET', url: '/simple', headers: { Authorization: `Basic ${headerString}` } });
          expect(response.statusCode).to.equal(401);
        });
      });
    });
  });

  describe('OAUTH2', () => {
    const tokenHeader = `Bearer ${mockToken}`;
    const hashedToken = MD5(mockToken);

    it('returns  401 for requests without auth headers', async () => {
      const response = await server.inject('/oauth');
      expect(response.statusCode).to.be.eq(401);
    });

    describe('redis caches authentication', () => {
      const token = { sub: '234234' };

      before(async () => {
        await flushCache();
        return redisClient.setAsync(`openam:${hashedToken}`, JSON.stringify(token));
      });

      it('checks for an existing oauth2 token to auth', async () => {
        const response = await server.inject({ method: 'GET', url: '/oauth', headers: { Authorization: tokenHeader } });
        expect(response.statusCode).to.be.eq(200);
        expect(requestUser.sub).to.be.eq('234234');
      });

      it('returns downstream errors as is', async () => {
        const response = await server
          .inject({ method: 'GET', url: '/oauth_err', headers: { Authorization: tokenHeader } });
        expect(response.statusCode).to.be.eq(500);
      });
    });

    describe('redis expires tokens with oauth2 strategy ', () => {
      before(async () => {
        await flushCache();
        openAMMock
          .get(`${openAMInfoPath}?access_token=${mockToken}`)
          .reply(200, {
            agcoUUID: agcoUuid,
            scope: ['agcoUUID', 'username', 'email'],
            username: 'demo',
            email: 'foo@bar.com',
            expires_in: 2
          });
        return server.inject({ method: 'GET', url: '/oauth', headers: { Authorization: tokenHeader } });
      });

      it('expires the cached token', async () => {
        const token = await redisClient.getAsync(`openam:${hashedToken}`);
        expect(token).to.not.be.eq(null);
        await Promise.delay(4000);
        const noToken = await redisClient.getAsync(`openam:${hashedToken}`);
        expect(noToken).to.be.eq(null);
      });
    });

    describe('Tokens not in redis', () => {
      describe('valid request', () => {
        before(async () => {
          await flushCache();
          openAMMock
            .get(`${openAMInfoPath}?access_token=${mockToken}`)
            .reply(200, {
              agcoUUID: agcoUuid,
              scope: ['agcoUUID', 'username', 'email'],
              username: 'demo',
              email: 'foo@bar.com',
              expires_in: 500
            });
        });

        it('gets valid users info and caches it in redis', async () => {
          const response = await server
            .inject({ method: 'GET', url: '/oauth', headers: { Authorization: tokenHeader } });
          expect(response.statusCode).to.equal(200);
          expect(requestUser.sub).to.equal(agcoUuid);
          const token = await redisClient.getAsync(`openam:${hashedToken}`);
          expect(JSON.parse(token).sub).to.equal(agcoUuid);
        });
      });

      describe('token not found on open am', () => {
        before(async () => {
          await flushCache();
          openAMMock
            .get(`${openAMInfoPath}?access_token=${mockToken}`)
            .reply(404);
        });

        it('invalidates a user', async () => {
          const response = await server
            .inject({ method: 'GET', url: '/oauth', headers: { Authorization: tokenHeader } });
          expect(response.statusCode).to.equal(401);
          const token = await redisClient.getAsync(`openam:${hashedToken}`);
          expect(token).to.equal(null);
        });
      });
    });
  });
});
