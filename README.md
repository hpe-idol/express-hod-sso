# express-hod-sso

[Express](http://expressjs.com/) (4.x) middleware for securing routes using [HPE Haven OnDemand](http://www.havenondemand.com) SSO.

Designed for use with the [node-hod-request-lib](https://github.com/hpe-idol/node-hod-request-lib), [hod-sso-js](https://github.com/hpe-idol/hod-sso-js) and a compatible token repository.

The currently supported token repository implementations are limited to:

* (In memory) simple token repository included as part of the [node-hod-request-lib](https://github.com/hpe-idol/node-hod-request-lib)
* [Redis token repository](https://github.com/hpe-idol/node-redis-hod-token-repository)

## Usage

express-hod-sso exposes an Express Router for use as middleware/routing:

    var ssoRouter = require('express-hod-sso');

    app.use(ssoRouter(apiKey, {
        allowedOrigins: allowedOrigins,
        hodRequestLib: hodRequestLib,
        tokenRepository: tokenRepository
    }));

## License
Copyright 2016 Hewlett Packard Enterprise Development LP

Licensed under the MIT License (the "License"); you may not use this project except in compliance with the License.
