var express = require('express');
var http = require('http');

var HodRequestLib = require('hod-request-lib');
var HodAuthentication = require('./src/authentication');
var debug = require('./src/services/debug');


module.exports = expressHodSso;

/**
 * @typedef {Object} SsoOptions
 * @property {Object} [hodRequestLib] Reference to an instance of the HoD Request Lib with which to make HoD requests.
 * @property {Object} [tokenRepository] Reference to an instance of a token repository with which to store HoD tokens.
 * @property {string} [errorPage] Path to attach an error page route to, defaults to '/error'.
 * @property {string} [errorView] Name of the error view the error route renders, defaults to 'error'.
 * @property {string} [ssoPage] Path to attach an sso page route to, defaults to '/sso'.
 * @property {string} [ssoView] Name of the sso view the sso route renders, defaults to 'sso'. This page should contain javascript that handles the HoD authentication process. See https://github.com/hpautonomy/hod-sso-js for an implementation.
 * @property {string} [authenticatePath] Path to attach an authenticate route to, defaults to '/authenticate'.  In most cases you should leave this as the default.
 * @property {string} [combinedRequestPath] Path to attach a combined request route to, defaults to 'api/combined-request'.
 * @property {string} [hodApiHost] API endpoint to use for Haven OnDemand, defaults to 'api.havenondemand.com'.
 * @property {string} [hodSsoPage] URL of the Haven OnDemand SSO page, defaults to 'https://www.havenondemand.com/sso.html'.
 * @property {string} [protectedRoutePath] An express route path that describes all the routes to protect with SSO, defaults to '*' to protect all endpoints.
 * @property {Array<string>} [allowedOrigins] All allowed origin URLs, defaults to ['http://localhost:8080'].
 */
/**
 *
 * @param {string} apiKey HoD application API key to authenticate against.
 * @param {SsoOptions} options Configuration options.
 * @returns {*} An express router to attach to the root of the application.
 */
function expressHodSso(apiKey, options) {

    var opts = options || {};
    var hodRequests = opts.hodRequestLib || new HodRequestLib({});
    var tokenRepository = opts.tokenRepository;
    var errorPage = opts.errorPage || '/error';
    var errorView = opts.errorView || 'error';
    var ssoPage = opts.ssoPage || '/sso';
    var ssoView = opts.ssoView || 'sso';
    var authenticatePath = opts.authenticatePath || '/authenticate';
    var combinedRequestPath = opts.combinedRequestPath || '/api/combined-request';
    var hodApiHost = opts.hodApiHost || 'api.havenondemand.com';
    var hodSsoPage = opts.hodSsoPage || 'https://www.havenondemand.com/sso.html';
    var allowedOrigins = opts.allowedOrigins || ['http://localhost:8080'];
    var protectedRoutePath = opts.protectedRoutePath || '*';

    var auth = new HodAuthentication(apiKey, hodApiHost, allowedOrigins, hodRequests, tokenRepository);

    var router = express.Router();

    /*
        Haven OnDemand error during any part of the authentication
        process should be redirected to the application error page.
     */
    var onHodError = function(res, hodResponse) {
        var code = (hodResponse && hodResponse.httpStatusCode) || 500;
        res.redirect(errorPage + '?statusCode=' + code);
    };

    /*
        Fetch the signed combined-get request before rendering the
        application SSO page, which should contain javascript to
        perform the client part of the authentication.
     */
    router.get(ssoPage, function(req, res) {
        if(req.query.error) {
            debug.error('HoD SSO page has redirected with error query param, redirecting to error.');
            res.redirect(errorPage + '?error=' + req.query.error);
        } else {
            auth.combinedGetSignature(function(err, response){
                if(err) {
                    debug.error('Error while fetching signed combined-get request, redirecting.');
                    onHodError(res, response);
                } else {
                    debug.log('Rendering the SSO page.');
                    res.render(ssoView, {
                        configJson: JSON.stringify({
                            authenticatePath: authenticatePath,
                            errorPage: errorPage,
                            combinedRequestApi: combinedRequestPath,
                            listApplicationRequest: response,
                            ssoPage: hodSsoPage,
                            ssoEntryPage: ssoPage
                        })
                    });
                }
            });
        }
    });

    /*
        App SSO page calls this path (previously passed as option to
        render method) to populate the session with token info.
     */
    router.post(authenticatePath, function(req, res) {
        auth.authenticateUntrustedCombinedToken(req.body, function(err, result) {
            if(err) {
                debug.error('Error while authenticating combined token, redirecting');
                onHodError(res, result);
            } else if(!result) {
                debug.log('Combined token failed authentication, redirecting');
                res.redirect(errorPage + '?statusCode=401');
            } else {
                debug.log('Authenticated combined token, setting token proxy and redirecting to original requested endpoint.');
                tokenRepository.insert(result, function(err, tokenProxy) {
                    if(err) {
                        debug.error('Generating a token proxy failed, redirecting to error.');
                        res.status(500).redirect(errorPage);
                    } else {
                        req.session.tokenProxy = tokenProxy;
                        res.redirect(req.session.unauthorizedRequestUrl || '/');
                    }
                });
            }
        });
    });

    /*
        Combined-post endpoint for the app SSO page to call. Sets domain
        on the session while we have it.
     */
    router.get(combinedRequestPath, function(req, res) {
        auth.combinedPostSignature(
            req.query.domain,
            req.query.application,
            req.query['user-store-domain'],
            req.query['user-store-name'],
            function(err, result) {
                if(err) {
                    debug.error('Error while fetching signed combined-post request, redirecting.');
                    onHodError(res, result);
                } else if(!req.session) {
                    var message = 'No valid session found. Session store may be down.';
                    debug.error(message);
                    res.status(500).send(message);
                } else {
                    debug.log('Combined-post signature request success, returning JSON to SSO page.');
                    req.session.domain = req.query.domain;
                    res.json(result);
                }
            })
    });

    /*
        Error page route handler
     */
    router.get(errorPage, function(req, res) {
        res.render(errorView, {
            error: http.STATUS_CODES[req.query.statusCode] || req.query.error || '',
            status: req.query.statusCode
        });
    });

    /*
        Check user is authenticated on all protected paths.
     */
    router.all(protectedRoutePath, function(req, res, next) {
        auth.authenticateRequest(req, function(err, isAuthenticated) {
            if(err || !isAuthenticated) {
                debug.error('Unauthenticated request made to ' + req.path);
                if(req.xhr) {
                    res.status(401).send({ error: 'Invalid session' });
                } else {
                    if (req.session) req.session.unauthorizedRequestUrl = req.originalUrl;
                    res.redirect(ssoPage);
                }
            } else {
                debug.log('Request authenticated');
                next();
            }
        });
    });

    return router;
}