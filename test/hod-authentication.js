var proxyquire = require('proxyquire');
var sinon = require('sinon');
var should = require('should');

describe('HoD Authentication', function() {
    var auth;
    var tokenRepository = new (require('hod-request-lib').SimpleTokenRepository)();
    var HodRequestLib = require('hod-request-lib');
    var hodRequests;
    var tokens = HodRequestLib.tokens;

    var signature = 'signature';
    var applicationObj = { auth: { uuid: 'uuid' }};
    var tokenProxy = 'abc';
    var token = { expiry: (new Date()).getTime() + 1000000, application: applicationObj };
    var apiKey = 'apikey';
    var endpoint = 'api.fake.haveondemand.com';
    var allowedOrigins = ['http://allowed.origins1.com', 'http://allowed.origins2.com'];

    beforeEach(function () {
        sinon.stub(tokens, 'stringForSignedRequest').returns(signature);
        sinon.stub(tokens, 'stringFromToken').returns(token);
        sinon.stub(HodRequestLib.prototype, 'tokenInformation').callsArgWith(1, null, { result: { token: applicationObj }});
        sinon.stub(HodRequestLib.prototype, 'authenticateUnboundHmac').callsArgWith(1, null, { result: { token: token }});
        sinon.stub(tokenRepository, 'get').callsArgWith(1, null, token);
        hodRequests = new HodRequestLib({});

        auth = new (proxyquire('../src/authentication', {
            tokens: tokens
        }))(apiKey, endpoint, allowedOrigins, hodRequests, tokenRepository);
    });

    afterEach(function () {
        tokens.stringFromToken.restore();
        tokens.stringForSignedRequest.restore();
        hodRequests.tokenInformation.restore();
        hodRequests.authenticateUnboundHmac.restore();
        tokenRepository.get.restore();
    });

    describe('HodAuthentication constructor', function () {
        it('should set the correct apikey', function() {
            auth.apiKey.should.equal(apiKey);
        });

        it('should set the correct allowed origins array', function() {
            auth.allowedOrigins.should.equal(allowedOrigins);
        });

        it('should set the correct authenticate combined URL', function() {
            auth.authenticateCombinedUrl.should.startWith('https://' + endpoint);
            auth.authenticateCombinedUrl.should.endWith('allowed_origins=' + allowedOrigins[0] + '&allowed_origins=' + allowedOrigins[1]);
        });
    });

    describe('populateUnboundToken', function () {
        it('should fetch unbound token and app uuid on the first request only', function (done) {
            auth.populateUnboundToken(function (err) {
                (err === null).should.be.true();

                hodRequests.authenticateUnboundHmac.restore();
                sinon.stub(hodRequests, 'authenticateUnboundHmac').yields('Error', null);
                sinon.stub(auth, 'getHmacTokenInformation').yields('Error', null);
                auth.populateUnboundToken(function (err) {
                    (err === null).should.be.true();
                    auth.getHmacTokenInformation.restore();
                    done();
                })
            });
        });

        it('should call callback with an error', function (done) {
            hodRequests.authenticateUnboundHmac.restore();
            sinon.stub(hodRequests, 'authenticateUnboundHmac').yields('Error');

            auth.populateUnboundToken(function(err) {
                err.should.equal('Error');
                done();
            });
        });
    });

    describe('authenticateRequest', function () {
        it('should call callback with false if given a non-authenticated request', function (done) {
            auth.authenticateRequest({}, function(err, result) {
                (err === null).should.be.true();
                (!result).should.be.true();
                done();
            });
        });

        it('should call callback with true if given an authenticated request', function (done) {
            auth.authenticateRequest({
                session: {
                    tokenProxy: tokenProxy
                }
            }, function (err, result) {
                (err === null).should.be.true();
                result.should.be.ok();
                done();
            });
        });
    });

    describe('authenticateUntrustedCombinedToken', function() {
        beforeEach(function() {
            sinon.stub(auth, 'populateUnboundToken').yields(null);
            sinon.stub(auth, 'getTokenInformation').yields(null, token);
        });

        afterEach(function() {
            auth.populateUnboundToken.restore && auth.populateUnboundToken.restore();
            auth.getTokenInformation.restore();
        });

        it('should call populateUnboundToken', function(done) {
            auth.authenticateUntrustedCombinedToken(token, function() {
                auth.getTokenInformation.calledOnce.should.be.true();
                done();
            });
        });

        it('should call getTokenInformation with the token', function(done) {
            auth.authenticateUntrustedCombinedToken(token, function() {
                auth.getTokenInformation.calledOnce.should.be.true();
                auth.getTokenInformation.args[0][0].should.equal(token);
                done();
            });
        });

        it('should return a falsy value for a non-authenticated token', function(done) {
            auth.authenticateUntrustedCombinedToken({}, function(err, authenticated) {
                should(authenticated).not.be.ok();
                done();
            });
        });

        it('should return a truthy value for an authenticated token', function(done) {
            auth.populateUnboundToken.restore();
            auth.authenticateUntrustedCombinedToken(token, function(err, authenticated) {
                authenticated.should.be.ok();
                done();
            });
        });
    });

    describe('getTokenInformation', function() {
        it('should call the callback with the token response', function (done) {
            auth.getTokenInformation(token, function(err, response) {
                (err === null).should.be.true();
                response.should.be.eql(applicationObj);
                done();
            });
        });

        it('should call the callback with an error if the request returns one', function (done) {
            hodRequests.tokenInformation.restore();
            sinon.stub(hodRequests, 'tokenInformation').callsArgWith(1, 'Error');

            auth.getTokenInformation(token, function(err) {
                err.should.be.equal('Error');
                done();
            });
        });
    });

    describe('getHmacTokenInformation', function() {
        it('should call the callback with the token info response', function (done) {
            hodRequests.tokenInformation.restore();
            sinon.stub(hodRequests, 'tokenInformation')
                .withArgs(signature)
                .callsArgWith(1, null, token);

            auth.getHmacTokenInformation(token, function(err, response) {
                (err === null).should.be.true();
                response.should.equal(token);
                done();
            });
        });
    });

    describe('getCombinedSignedRequest', function() {
        beforeEach(function() {
            sinon.stub(auth, 'populateUnboundToken').yields(null, {});
        });

        afterEach(function() {
            auth.populateUnboundToken.restore();
        });

        it('should call populateUnboundToken', function(done) {
            auth.getCombinedSignedRequest('GET', {}, allowedOrigins, function() {
                auth.populateUnboundToken.calledOnce.should.be.true();
                done();
            });
        });

        it('should call the callback with an error if populateUnboundToken returns an error', function(done) {
            auth.populateUnboundToken.restore();
            sinon.stub(auth, 'populateUnboundToken').yields('Error');
            auth.getCombinedSignedRequest('GET', {}, allowedOrigins, function(err) {
                err.should.be.ok();
                done();
            });
        });

        it('should call the callback with the signature returned by tokens.stringForSignedRequest', function(done) {
            auth.getCombinedSignedRequest('GET', {}, allowedOrigins, function(err, result) {
                result.should.equal(signature);
                done();
            });
        });
    });

    describe('combinedGetSignature', function() {
        it('should call the callback with the appropriate signed request', function (done) {
            auth.combinedGetSignature(function(err, response) {
                (err === null).should.be.true();
                response.should.property('url');
                response.should.property('verb', 'GET');
                response.should.property('token', signature);
                done();
            });
        });

        it('should call the callback with an error if unable to get unbound token', function (done) {
            hodRequests.authenticateUnboundHmac.restore();
            sinon.stub(hodRequests, 'authenticateUnboundHmac').callsArgWith(1, 'Error');

            auth.combinedGetSignature(function(err) {
                err.should.be.equal('Error');
                done();
            });
        });
    });

    describe('combinedPostSignature', function() {
        var mockArgs = ['any', 'old', 'arg', 'values'];

        it('should call the callback with the appropriate signed request', function (done) {
            mockArgs.push(function(err, response) {
                (err === null).should.be.true();
                response.should.property('url');
                response.should.property('verb', 'POST');
                response.should.property('token', signature);
                response.should.property('body');
                done();
            });

            auth.combinedPostSignature.apply(auth, mockArgs);
            mockArgs.pop();
        });

        it('should call the callback with an error if unable to get unbound token', function (done) {
            hodRequests.authenticateUnboundHmac.restore();
            sinon.stub(hodRequests, 'authenticateUnboundHmac').callsArgWith(1, 'Error');

            mockArgs.push(function(err) {
                (err === null).should.be.false();
                done();
            });

            auth.combinedPostSignature.apply(auth, mockArgs);
            mockArgs.pop();
        });
    });
});
