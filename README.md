# Hapi-OpenAM

### Integrating OpenAM with Hapi authentication plugins

This provides the validateFunc for the following hapi plugins:
```
hapi-auth-basic
hapi-auth-bearer-token
```

### Example usage
```
server = new Hapi.Server();
server.connection({ port: 5050});
server.register([
  {register: require('hapi-auth-basic')},
  {register: require('hapi-auth-bearer-token')}
], (err) => {
    if(err) throw err;
    server.auth.strategy('simple', 'basic', { validateFunc: openAM.basicStrategyValidate(basicOptions) });
    server.route({ method: 'GET', path: '/simple', config: { auth: 'simple' }, handler: function (request, reply) { return reply('ok'); } });

    server.auth.strategy('oauth2', 'bearer-access-token', { validateFunc: openAM.bearerTokenStrategyValidate(oauth2Options) });
    server.route({ method: 'GET', path: '/oauth', config: { auth: 'oauth2' }, handler: function (request, reply) { return reply('ok'); } });

    server.start(done);
})
```

### Caching

#### Redis

A redis instance is required to cache users authentication

### A word about `node` versions.

This was written using the ES6 implementation in Node 4.2.x
