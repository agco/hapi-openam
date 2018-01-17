const redis = require('redis');
const Promise = require('bluebird');
const md5 = require('MD5');
const request = require('request-promise');
const debug = require('debug')('openam');

Promise.promisifyAll(redis.RedisClient.prototype);
Promise.promisifyAll(redis.Multi.prototype);

const cacheKeyPrefix = 'openam';

const redisDefaults = {
  retry_strategy: (options) => {
    const maxRetries = 20;
    const retryTimeout = 1000 * 60 * 60;
    if (options.total_retry_time > retryTimeout) {
      return new Error('Retry time exhausted', options.error);
    }
    if (options.times_connected > maxRetries) {
      return new Error('Max retries exceeded', options.error);
    }
    return Math.max(options.attempt * 100, 3000);
  }
};

module.exports = (options) => {
  debug('Initialized OpenAM auth', options);
  const redisOptions = Object.assign(options.redis || {}, redisDefaults);
  const redisClient = redis.createClient(redisOptions);
  const url = options.openAMBaseURL;
  const infoUrl = options.openAMInfoURL;
  const scope = options.scope ? options.scope.join(' ') : '';
  const clientId = options.client_id;
  const clientSecret = options.client_secret;

  const postToken = (username, password) => {
    const post = {
      url,
      form: {
        client_id: clientId,
        client_secret: clientSecret,
        grant_type: 'password',
        username,
        password,
        scope
      },
      json: true
    };
    return request.post(post);
  };

  const cacheUser = (keySuffix, expires, user) => {
    const key = `${cacheKeyPrefix}:${keySuffix}`;
    debug('cache token args', key, expires, user);
    return redisClient.setexAsync(key, expires, JSON.stringify(user));
  };

  const getUser = async (accessToken, cacheKey) => {
    const get = {
      url: `${infoUrl}?access_token=${accessToken}`,
      json: true
    };
    const token = await request.get(get);
    const user = { sub: token.agcoUUID, token };
    const expires = token.expires_in;
    await cacheUser(cacheKey, expires, user);
    return user;
  };

  const getCachedUser = (keySuffix) => {
    const key = `${cacheKeyPrefix}:${keySuffix}`;
    return redisClient.getAsync(key);
  };

  const success = user => ({ isValid: true, credentials: user });

  const failure = () => ({ isValid: false, credentials: {} });

  const basicStrategyValidate = async (req, username, password) => {
    debug(`openam got auth request for user: ${username}`);
    const header = `${username}:${password}`;
    const cacheKey = md5(header);
    const cachedUser = await getCachedUser(cacheKey);
    if (cachedUser) {
      debug(`got user from cache for key: ${cacheKey}`, cachedUser);
      return success(JSON.parse(cachedUser));
    }
    try {
      const tokenResult = await postToken(username, password);
      const user = await getUser(tokenResult.access_token, cacheKey);
      return success(user);
    } catch (err) {
      debug(err);
      if (err.statusCode === 400 || err.statusCode === 404) {
        return failure();
      }
      throw err;
    }
  };

  const bearerTokenStrategyValidate = async (req, accessToken) => {
    debug(`openam got auth request for access token: ${accessToken}`);
    const cacheKey = md5(accessToken);
    const cachedUser = await getCachedUser(cacheKey);
    if (cachedUser) {
      debug(`got user from cache for key: ${cacheKey}`, cachedUser);
      return success(JSON.parse(cachedUser));
    }
    try {
      const user = await getUser(accessToken, cacheKey);
      return success(user);
    } catch (err) {
      debug(err);
      if (err.statusCode === 400 || err.statusCode === 404) {
        return failure();
      }
      throw err;
    }
  };

  return { basicStrategyValidate, bearerTokenStrategyValidate };
};
