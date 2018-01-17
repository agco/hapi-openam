# Hapi-OpenAM

**Note: The `develop` branch and Version 2.x is only compatible with hapi v17 and above.**

### Integrating OpenAM with Hapi authentication plugins

This provides the `validate` function for the following hapi plugins:
```
hapi-auth-basic
hapi-auth-bearer-token
```

### Example usage
```
server = Hapi.Server();
server.connection({ port: 8080 });
await server.register(require('hapi-auth-basic'));
await server.register(require('hapi-auth-bearer-token'));

const basicOptions = {
  redis: {
    host: 'http://localhost',
    port: 6379,
    password: 'auth',
    no_ready_check: true
  },
  openAMBaseURL: 'https://openamserver/auth/oauth2/access_token?realm=/dealers',
  openAMInfoURL: 'https://openamserver/auth/oauth2/tokeninfo',
  client_id: 'clientid',
  client_secret: 'clientsecret',
  scope: ['mail', 'cn', 'agcoUUID']
};

server.auth.strategy('simple', 'basic', { validate: openAM(basicOptions).basicStrategyValidate });
server.route({
  method: 'GET',
  path: '/simple',
  config: { auth: 'simple' },
  handler: () => 'ok'
});

const oauth2Options = {
  redis: {
    host: 'http://localhost',
    port: 6379,
    password: 'auth',
    no_ready_check: true
  },
  openAMInfoURL: 'https://openamserver/auth/oauth2/tokeninfo'
};

server.auth.strategy('oauth2', 'bearer-access-token', { validate: openAM(oauth2Options).bearerTokenStrategyValidate });
server.route({
  method: 'GET',
  path: '/oauth',
  config: { auth: 'oauth2' },
  handler: () => 'ok'
});
await server.start();
```

### Caching

#### Redis

A redis instance is required to cache users authentication

### A word about `node` versions.

This was written using async/await and required node version 7.6 or higher.
