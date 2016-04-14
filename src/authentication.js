var formUrlEncoded = require('form-urlencoded');
var async = require('async');

var HodRequestLib = require('hod-request-lib');
var getPath = require('./get-path-safe');

var REFRESH_THRESHOLD = 10000; //10 seconds
var AUTHENTICATE_COMBINED_PATH = '/2/authenticate/combined';

module.exports = HodAuthentication;

function HodAuthentication(apiKey, hodApiHost, allowedOrigins, hodRequests, tokenRepository) {
    this.hodRequestLib = hodRequests;
    this.tokenRepository = tokenRepository;
    this.apiKey = apiKey;
    this.allowedOrigins = allowedOrigins;
    this.authenticateCombinedUrl = 'https://' + hodApiHost +
        AUTHENTICATE_COMBINED_PATH + '?' +
        'allowed_origins=' + allowedOrigins.join('&allowed_origins=');
    this.unboundToken = null;
    this.applicationUuid = null;
}

/*
 Check token is authenticated. Optionally checks for valid application UUID
 */
function authenticateToken(checkAppUuid) {
    return function(token, callback) {
        var authenticAppUuid = !checkAppUuid || this.applicationUUID === getPath(token, 'application.auth.uuid');
        var authenticated = token.expiry > Date.now() && authenticAppUuid;

        return callback(null, authenticated ? token : null);
    }
}
var authenticateTrustedToken = authenticateToken(false);
var authenticateUntrustedToken = authenticateToken(true);

/*
    Make HoD request to fetch unbound token
 */
function fetchUnboundToken(callback) {
    this.hodRequestLib.authenticateUnboundHmac(this.apiKey, function(err, response) {
        if(err) return callback(err, response);

        return callback(null, response.result.token);
    });
}

/*
    Fetch application uuid using the previously fetched unbound token
 */
function fetchApplicationUuid(callback, results) {
    this.getHmacTokenInformation(results.unboundToken, function(err, hodResponse) {
        if(err) return callback(err);

        return callback(null, getPath(hodResponse, 'result.token.auth.uuid'));
    });
}

/*
    If we don't already have the application unbound token, fetch this and
    the application UUID which we will need for checking a user is authenticated.
 */
HodAuthentication.prototype.populateUnboundToken = function(callback) {
    var validUnboundToken = this.unboundToken && this.unboundToken.expiry >= (Date.now() - REFRESH_THRESHOLD);
    async.auto({
        unboundToken: validUnboundToken ? async.constant(this.unboundToken) : fetchUnboundToken.bind(this),
        applicationUuid: ['unboundToken', this.applicationUUID ? async.constant(this.applicationUUID) : fetchApplicationUuid.bind(this)]
    }, (function(err, results) {
        this.unboundToken = results.unboundToken;
        this.applicationUUID = results.applicationUuid;
        return callback(err, results.unboundToken);
    }).bind(this));
};

/*
    Check request is authenticated. Session must contain a token proxy
    that maps to a token that has not yet expired.
 */
HodAuthentication.prototype.authenticateRequest = function(req, callback) {
    var tokenProxy = req.session && req.session.tokenProxy;
    if(!tokenProxy) return callback(null, false);

    return this.tokenRepository.get(tokenProxy, (function(err, token) {
        if (err || !token) return callback(err, false);

        return authenticateTrustedToken.call(this, token, callback);
    }).bind(this));
};


/*
    Check token is authenticated, uses an application UUID check, for which
    we may have to fetch token information.
 */
HodAuthentication.prototype.authenticateUntrustedCombinedToken = function(token, callback) {
    async.auto({
        unboundToken: this.populateUnboundToken.bind(this),
        token: this.getTokenInformation.bind(this, token),
        authenticate: ['unboundToken', 'token', (function(callback, results) {
            token.application = getPath(results, 'token.application');
            token.tenant_uuid = getPath(results, 'token.tenant_uuid');
            token.user = getPath(results, 'token.user');
            token.user_store = getPath(results, 'token.user_store');

            return authenticateUntrustedToken.call(this, token, callback)
        }).bind(this)]
    }, function(err, results) {
        return callback(err, results.authenticate)
    });
};


/*
    Return further information about any given token.
 */
HodAuthentication.prototype.getTokenInformation = function(token, callback) {
    this.hodRequestLib.tokenInformation(HodRequestLib.tokens.stringFromToken(token), function(err, response) {
        if(err) return callback(err, response);

        return callback(null, response.result.token);
    });
};

/*
    Return further information about an HMAC token.
 */
HodAuthentication.prototype.getHmacTokenInformation = function(token, callback) {
    var signature = HodRequestLib.tokens.stringForSignedRequest(token, {
        path: '/2/authenticate',
        method: 'GET',
        query: []
    });

    this.hodRequestLib.tokenInformation(signature, callback);
};

/*
 Fetch the HMAC token for a signed request
 */
HodAuthentication.prototype.getCombinedSignedRequest = function(method, body, allowedOrigins, callback) {
    this.populateUnboundToken(function(err, response) {
        if(err) return callback(err, response);

        var signature = HodRequestLib.tokens.stringForSignedRequest(response, {
            path: AUTHENTICATE_COMBINED_PATH,
            method: method,
            query: [
                ['allowed_origins', allowedOrigins]
            ],
            body: body
        });

        return callback(null, signature);
    });
};

/*
    Retrieves a signed combined get request that can be made client-side.
 */
HodAuthentication.prototype.combinedGetSignature = function(callback) {
    var method = 'GET';
    var self = this;

    this.getCombinedSignedRequest(method, {}, this.allowedOrigins, function(err, response) {
        if(err) return callback(err, response);

        var signedRequest = {
            url: self.authenticateCombinedUrl,
            verb: method,
            token: response
        };

        return callback(null, signedRequest);
    })
};

/*
    Retrieves a signed combined post request that can be made client-side.
 */
HodAuthentication.prototype.combinedPostSignature = function(domain, application, userStoreDomain, userStoreApplication, callback) {
    var method = 'POST';
    var self = this;

    var body = {
        token_type: 'simple',
        domain: domain,
        application: application,
        userstore_domain: userStoreDomain,
        userstore_name: userStoreApplication
    };

    this.getCombinedSignedRequest(method, body, this.allowedOrigins, function(err, signature) {
        if(err) return callback(err);

        var signedRequest = {
            url: self.authenticateCombinedUrl,
            verb: method,
            token: signature,
            body: formUrlEncoded.encode(body)
        };

        return callback(null, signedRequest);
    })
};
