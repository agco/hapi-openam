'use strict';

const redis = require('redis');
const Promise = require('bluebird');
const md5 = require('MD5');
const $http = require('http-as-promised');
const debug = require('debug')('openam');

Promise.promisifyAll(redis.RedisClient.prototype);
Promise.promisifyAll(redis.Multi.prototype);

const basicKey = (s) => {
  return `${s}-basic`;
};

const oauth2Key = (s) => {
  return `${s}-oauth2`;
};

module.exports = {
  basicKey,
  oauth2Key,
  basicStrategyValidate: (options) => {
    debug('created basic strategy validation', options);
    return (request, username, password, done) => {
      debug(`openam got auth request for user: ${username}`);
      const redisClient = redis.createClient(options.redis);
      const header = `${username}:${password}`;
      const hashedHeader = basicKey(md5(header));
      const URL = options.openAMBaseURL;
      const infoURL = options.openAMInfoURL;
      const scopes = options.scope.join(' ');

      const postToken = () => {
        return $http.post(URL, {
          form: {
            client_id: options.client_id,
            client_secret: options.client_secret,
            grant_type: 'password',
            username,
            password,
            scope: scopes
          },
          error: true,
          json: true
        });
      };

      const getTokenInfo = (tokenBody) => {
        return $http.get(`${infoURL}?access_token=${tokenBody.access_token}`, { json: true })
          .spread((res, infoBody) => {
            const user = { sub: infoBody.agcoUUID, token: infoBody };
            infoBody.sub = infoBody.agcoUUID;
            debug(`got token info for: ${hashedHeader}`);
            return [hashedHeader, user, tokenBody.expires_in];
          });
      };

      const cacheToken = (hHeader, tokenInfo, expiry) => {
        debug('cache token args', hHeader, tokenInfo, expiry);
        return redisClient
          .multi()
          .set(hHeader, JSON.stringify(tokenInfo))
          .expire(hHeader, expiry)
          .execAsync()
          .then(() => {
            debug('cached token');
            return tokenInfo;
          });
      };

      const getandCacheTokenInfo = (res, body) => {
        return getTokenInfo(body)
          .spread(cacheToken);
      };

      const returnToken = (tokenInfo) => {
        return done(null, true, tokenInfo);
      };

      const invalidate = () => {
        return done(null, false);
      };

      return redisClient
        .getAsync(hashedHeader)
        .then((tokenInfo) => {
          if (tokenInfo) {
            debug(`got tokeninfo from cache for hash: ${hashedHeader}`, tokenInfo);
            return done(null, true, JSON.parse(tokenInfo));
          }
          return postToken()
            .spread(getandCacheTokenInfo)
            .then(returnToken);
        })
        .catch(invalidate);
    };
  },
  bearerTokenStrategyValidate: (options) => {
    debug('created bearer token strategy validation', options);
    return (token, done) => {
      const redisClient = redis.createClient(options.redis);
      const hashedToken = oauth2Key(md5(token));
      const infoURL = options.openAMInfoURL;

      const getTokenInfo = () => {
        return $http.get(`${infoURL}?access_token=${token}`, { json: true, error: false });
      };

      const checkResponse = (res, body) => {
        return body.error || res.statusCode === 404 ? null : body;
      };

      const validate = (user) => {
        return done(null, true, user);
      };

      const storeUser = (tokenInfo) => {
        const user = { sub: tokenInfo.agcoUUID };
        user.token = tokenInfo;
        return redisClient
          .multi()
          .set(hashedToken, JSON.stringify(user))
          .expire(hashedToken, tokenInfo.expires_in)
          .execAsync()
          .then(() => user);
      };

      const validateReturn = (tokenInfo) => {
        if (!tokenInfo) {
          return done(null, false);
        }
        return storeUser(tokenInfo)
          .then(validate);
      };

      const invalidate = (err) => {
        return done(err, false);
      };

      return redisClient
        .getAsync(hashedToken)
        .then((value) => {
          if (value) {
            return done(null, true, JSON.parse(value));
          } else {
            return getTokenInfo()
              .spread(checkResponse)
              .then(validateReturn);
          }
        })
        .catch(invalidate);
    };
  }
};
