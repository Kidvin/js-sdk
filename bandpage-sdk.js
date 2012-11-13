/**
 * Copyright 2012 RootMusic, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */


if(typeof bandpage === 'undefined') {
    var bandpage = {};
}

(function DecoratorDefinition(exports) {

    // Simple registry for the various decorating functions
    var decorators = {},

    /**
     * Registers new decorators
     * @param {String}   name used to reference the function
     * @param {Function} fn   the decorating function
     * @return {undefined}
     */
    registerDecorator = function registerDecorator(name, fn) {
        decorators[name] = fn;
    },

    /**
     * c/o Jason Anderson
     * @param {Function} fn the function to be wrapped / decorated
     * @param {<any>} ... handles argument arrays
     * @return {Function} curried version of first fn and array
     */
    decorate = function decorate(fn) {
        var decorations = [].slice.call(arguments, 1),
            cmd, name, args,
            curryFn,
            curryArgs;

        // support array syntax (will return curried version of first fn)
        if (Object.prototype.toString.call(fn) === '[object Array]') {
            curryFn = fn[0];
            curryArgs = fn.slice(1);
            // create curry
            fn = function() {
                var args = [].slice.call(arguments);
                return curryFn.apply(this, curryArgs.concat(args));
            };
        }

        while (decorations.length > 0) {
            cmd = [].concat(decorations.shift()); // convert to array
            name = cmd[0];
            args = [fn].concat(cmd.slice(1)); // fn is always first arg

            fn = decorators[name].apply(null, args);
        }

        return fn;
    };

    if(!exports.utility) {
        exports.utility = {};
    }

    exports.utility.registerDecorator = registerDecorator;
    exports.utility.decorate = decorate;

})(( typeof exports === "undefined" ) ? bandpage : exports );

/**
 * Packs up base64 encoding functions
 * decoding strings in bas64
 * @platform browser
 */

(function(exports) {

    // from https://raw.github.com/kvz/phpjs/master/functions/url/base64_decode.js
    function base64_decode (data) {
        // http://kevin.vanzonneveld.net
        // +   original by: Tyler Akins (http://rumkin.com)
        // +   improved by: Thunder.m
        // +      input by: Aman Gupta
        // +   improved by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
        // +   bugfixed by: Onno Marsman
        // +   bugfixed by: Pellentesque Malesuada
        // +   improved by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
        // +      input by: Brett Zamir (http://brett-zamir.me)
        // +   bugfixed by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
        // *     example 1: base64_decode('S2V2aW4gdmFuIFpvbm5ldmVsZA==');
        // *     returns 1: 'Kevin van Zonneveld'
        // mozilla has this native
        // - but breaks in 2.0.0.12!
        //if (typeof this.window['btoa'] == 'function') {
        //    return btoa(data);
        //}
        var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        var o1, o2, o3, h1, h2, h3, h4, bits, i = 0,
            ac = 0,
            dec = "",
            tmp_arr = [];

        if (!data) {
            return data;
        }

        data += '';

        do { // unpack four hexets into three octets using index points in b64
            h1 = b64.indexOf(data.charAt(i++));
            h2 = b64.indexOf(data.charAt(i++));
            h3 = b64.indexOf(data.charAt(i++));
            h4 = b64.indexOf(data.charAt(i++));

            bits = h1 << 18 | h2 << 12 | h3 << 6 | h4;

            o1 = bits >> 16 & 0xff;
            o2 = bits >> 8 & 0xff;
            o3 = bits & 0xff;

            if (h3 == 64) {
                tmp_arr[ac++] = String.fromCharCode(o1);
            } else if (h4 == 64) {
                tmp_arr[ac++] = String.fromCharCode(o1, o2);
            } else {
                tmp_arr[ac++] = String.fromCharCode(o1, o2, o3);
            }
        } while (i < data.length);

        dec = tmp_arr.join('');

        return dec;
    }

    // from https://raw.github.com/kvz/phpjs/master/functions/url/base64_encode.js
    function base64_encode (data) {
        // http://kevin.vanzonneveld.net
        // +   original by: Tyler Akins (http://rumkin.com)
        // +   improved by: Bayron Guevara
        // +   improved by: Thunder.m
        // +   improved by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
        // +   bugfixed by: Pellentesque Malesuada
        // +   improved by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
        // +   improved by: Rafał Kukawski (http://kukawski.pl)
        // *     example 1: base64_encode('Kevin van Zonneveld');
        // *     returns 1: 'S2V2aW4gdmFuIFpvbm5ldmVsZA=='
        // mozilla has this native
        // - but breaks in 2.0.0.12!
        //if (typeof this.window['atob'] == 'function') {
        //    return atob(data);
        //}
        var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        var o1, o2, o3, h1, h2, h3, h4, bits, i = 0,
            ac = 0,
            enc = "",
            tmp_arr = [];

        if (!data) {
            return data;
        }

        do { // pack three octets into four hexets
            o1 = data.charCodeAt(i++);
            o2 = data.charCodeAt(i++);
            o3 = data.charCodeAt(i++);

            bits = o1 << 16 | o2 << 8 | o3;

            h1 = bits >> 18 & 0x3f;
            h2 = bits >> 12 & 0x3f;
            h3 = bits >> 6 & 0x3f;
            h4 = bits & 0x3f;

            // use hexets to index into b64, and append result to encoded string
            tmp_arr[ac++] = b64.charAt(h1) + b64.charAt(h2) + b64.charAt(h3) + b64.charAt(h4);
        } while (i < data.length);

        enc = tmp_arr.join('');
        
        var r = data.length % 3;
        
        return (r ? enc.slice(0, r - 3) : enc) + '==='.slice(r || 3);

    }

    if(!exports.utility) {
        exports.utility = {};
    }

    exports.utility.base64_decode = base64_decode;
    exports.utility.base64_encode = base64_encode;

})(bandpage);

function makeJSONPParams(url, access_token, jsonp_query_param, namespace, callbackID) {
    // if any of these already exist in the url, then we will not add them again
    // token and errorset are always needed, adding the connector before the token

    var callback = "",
        theparams = "",
        connector = (url.indexOf('?') === -1) ? "?" : "&",
        token = (url.indexOf('access_token') === -1) ? 'access_token=' + access_token : "",
        errorset = (url.indexOf('errorset') === -1) ? "&errorset=JSONP" : "";

    // only if we have the parts should we create the callback param
    if( (typeof jsonp_query_param !== 'undefined') &&
        (typeof namespace !=='undefined') &&
        (typeof callbackID !== 'undefined')
    ) {
        callback = (url.indexOf(jsonp_query_param) === -1) ?
            '&' + jsonp_query_param + '=' + namespace
                + '.jsonpCallbacks.callback_' + callbackID : "";
    }

    theparams = token + errorset + callback;

    if(theparams === "") {
        return theparams;
    }

    return connector + theparams;
}

// transport constructors
(function(exports) {

    var namespace = 'bandpage',
        jsonp_query_param = "jsonp_callback",

        // Based on https://gist.github.com/722562
        /**
         * a transport based on jsonp requests, parses
         * responses with one or two arguments
         * @return {[type]}
         */
        jsonp_transport = {

            makeRequest: function(request, done, fail) {

                function evalJSONP(done, fail) {

                    function json_error() {
                        fail({ error : "JSONP call returned invalid or empty JSON" });
                    }

                    return function JSONCallback(/* data, response */) {
                        var validJSON = false,
                            data = null,
                            response = null;

                        if (arguments.length < 1) json_error();

                        // first arg should be data
                        data = Array.prototype.slice.call(arguments, 0, 1)[0];

                        if (arguments.length === 2) {
                            response = Array.prototype.slice.call(arguments, 1)[0];
                        }

                        if (typeof data === "string") {
                            try {
                                validJSON = JSON.parse(data);
                            } catch (e) {
                                /*invalid JSON*/
                                throw new Error(e);
                            }
                        } else {
                            // response data was not a JSON string
                            validJSON = JSON.parse(JSON.stringify(data));
                        }

                        if (validJSON) {
                            done(validJSON, response);
                        } else {
                            json_error();
                        }
                    };
                }

                if(typeof exports.callbackCounter === 'undefined') {
                    exports.callbackCounter = 0;
                }
                if(!exports) {
                    exports = {};
                }

                if(!exports.jsonpCallbacks) {
                    exports.jsonpCallbacks = {};
                }

                var callbackID = exports.callbackCounter++;

                exports.jsonpCallbacks['callback_' + callbackID] = evalJSONP(done, fail);

                var params = makeJSONPParams(request.url, request.access_token, jsonp_query_param, namespace, callbackID);
                request.path += params;
                request.url += params;

                var script = window.document.createElement('SCRIPT');
                script.src = request.url;
                script.async = true;
                //script.onerror = json_fail;
                window.document.getElementsByTagName('HEAD')[0].appendChild(script);
            }
        };

    exports.sdk_transports = {
        jsonp: jsonp_transport
    };

})(bandpage);

var browser_env = false,
    node_env = false,
    bandpage_env = false;

(function initEnvironment() {
    
    // we are likely in a node module
    if(typeof module !== 'undefined'
    && typeof module.exports !== 'undefined'
    && typeof window === 'undefined') {
        
        node_env = true;
    } else if(typeof window !== 'undefined') {

        browser_env = true;
        if(typeof bandpage !== 'undefined'
        && typeof bandpage.sdk_transports !== 'undefined') {

            bandpage_env = true;
        }
    } else {

        throw new Error(
            "unknown environment, please let us know where you are.");
    }
})();

/**
 *  sets up the utility object depending on the platform
 *  @returns {undefined}
 */
(function initUtility() {

    if(node_env) {
        var path = require('path');
        exports.utility = require(path.join(__dirname, "utility.js"));
    
    } else if( typeof bandpage.utility === "undefined" ) {

        throw new Error(
            "This build may be broken, cannot find utility module.");
    }
})();


(function(exports) {

    var NOW = 0,
        milliseconds_in_a_day = 86400000,
        has_credential = false,
        shared_secret,
        config = {},
        credential = {},
        protocol_sep = "://",
        version = {
            "param": "BP-SDK-Version",
            "language": "js",
            "version": "0.1"
        },
        default_config = {
            "host_protocol": "https",
            "host_uri": "api-read.bandpage.com",
            "host_port": 443,
            'path_prefix': "",
            "get_uri": "/",
            "token_uri": "/token"
        },
        allowed_config = [
            "host_protocol",
            "host_uri",
            "host_port",
            "path_prefix",
            "get_uri",
            "token_uri"
        ],
        default_credential = {
            "client_id": "",
            "shared_secret": "",
            "access_token": "",
            "token_type": "",
            "token_expiration": ""
        },
        private_credential = {
            "shared_secret":""
        },
        default_credential_flags = {
            "token_only": false,
            "public": false
        },
        default_options = {
            "done": function(data, response) {
                // throw new Error("you could provide a done callback");
            },
            "fail": function(data, response) {
                // throw new Error("you could provide a fail callback");
            }
        },
        required_options = {
            get: [
                "done",
                "fail",
                "bid"
            ],
            getConnections : [
                "done",
                "fail",
                "bid",
                "connection_type"
            ]
        },
        default_params = {
            get: {},
            getConnections: {
                "since": "",
                "until": "",
                "limit": 10
            }
        },
        allowed_params = {
            get: [],
            getConnections: [
                "since",
                "until",
                "limit"
            ]
        };

        /**
         *  @function
         *  a transport function must be passed to the init method
         *  we do look for and choose an available transport automatically
         *  @throws {Error} throws if transport is not auto-assigned.
         */
        var defaultTransportStrategy = function transportStrategy() {

            throw new Error("A transport strategy function must be specified.");
        },
        transportStrategy = defaultTransportStrategy;

    /**
     *  update the value of NOW, usually to check the credential expiration
     */
    function updateTime() {
        
        // the millisecond epoch at init
        NOW = new Date().getTime();
    }

    /**
     *  returns an array of keys missing from the given object
     *  are present in the given object
     *  @param {Array} required - an array of required options
     *  @param {Object} given - an object with keys that need validation
     *  @returns {Array}
     */
    function getObjectMissingKeys(required, given) {

        if(typeof given === "undefined") {
        
            return false;
        }
        
        var whatsmissing = [];

        for (var i=0; i<required.length; i++) {
            var key = required[i];
            // in case the key doesn't exist
            if(!given.hasOwnProperty(key)) whatsmissing.push(key);
            // or it does but the value is meh.. or worse nnhh..
            if( given.hasOwnProperty(key)
            &&((typeof given[key] === "undefined")
            || (given[key] === null)
            || (given[key] === "")   )) whatsmissing.push(key);
        }

        return whatsmissing;
    }

    /**
     *  merges properties from defaults into merge
     *  @param {Object} defaults - an object with default key/val pairs
     *  @param {Object} merge - an object that needs default key/vals
     *  @returns {Object} merge with any missing
     *                  fields filled from defaults
     */
    function shallowMerge(merge, defaults) {

        for (var prop in defaults) {

            if (!merge.hasOwnProperty(prop)
            || (merge.hasOwnProperty(prop)
                && typeof merge[prop] === "undefined")) {

                merge[prop] = defaults[prop];
            }
        }

        return merge;
    }

    /**
     *  returns a subset of an object based on an array of required keys
     *  @param {Array} required_keys - a set of key names
     *  @param
     *  @returns {Object} subset -
     *          object with keys from required and values from superset
     */
    function keySubset(required_keys, superset) {
        
        var subset = {};
        for (var i=0; i<required_keys.length; i++) {
        
            var key = required_keys[i];
            subset[key] = superset[key];
        }
        
        return subset;
    }

    /**
     *  removes properties in defaults from properties in base
     *  @param {Object} defaults - an object of key/val pairs
     *  @param {Object} base - an object from which properties will be removed
     *  @returns {Object} base without properties in defaults
     */
    function shallowSubtract(defaults, base) {
        
        for(var prop in defaults) {

            if(base.hasOwnProperty(prop)) {

                delete base[prop];
            }
        }
        
        return base;
    }

    /**
     * NOW is set at init by updateTime()
     */
    function now() {

        return NOW;
    }

    /**
     * get the milliseconds from today at 12:00am
     * which is now mod the 86400000 milliseconds in each day
     */
    function today() {

        var then = now();
        return then - (then % 86400000);
    }

    function clearCredential() {
        credential = {};
        has_credential = false;
    }

    function clearConfig() {
        config = {};
    }

    // check if we have a valid token
    function isValidToken() {

        updateTime();

        if( credential["access_token"] !== "" &&
          (credential["token_expiration"] > now())) {

            return true;
        }

        return false;
    }

    function getVersionHeader() {
        var header = {};
        header[version['param']] =
                     version['language'] + "/" + version['version'];
        return header;
    }

    // construct headers for an auth request
    function getAuthorizionHeader(length) {
        if(isValidToken()) {
            
            return {"Authorization": "Bearer " + credential["access_token"]};
        } else {

            if(!credential["shared_secret"]) {
                credential["shared_secret"] = shared_secret;
            }

            var authstring = credential["client_id"] +
                    ":" + credential["shared_secret"];
            return {
                "Authorization": "Basic " +
                        exports.utility.base64_encode(authstring),
                        "Content-Type" : "application/x-www-form-urlencoded;"
            };
        }
    }

    function processAPIKeyParam(params) {
        if(has_credential && credential.hasOwnProperty("apiKey")) {
            params["apiKey"] = credential["apiKey"];
        }
    }

    // construct the parameters for our auth request
    function getAuthorizationParams() {
        return {
            "client_id": credential["client_id"],
            "shared_secret": credential["shared_secret"],
            "grant_type":"client_credentials"
        };
    }

    function getParamString(params, post) {

        processAPIKeyParam(params);

        var prefix = !post ? "?" : "";

        // if there are no params, it'll be removed in the return expression
        var paramstring = "";

        for (var param in params) {
            paramstring += param + "=" + params[param] + "&"
        }
        if(paramstring === "") {
            return paramstring;
        } else {
            // add the question mark and remove the final &
            return prefix + paramstring.substr(0, paramstring.length-1);
        }
    }

    function decodeOptionally(data) {
        var decoded_data = null;
        try {
            decoded_data = JSON.parse(data);
        } catch(e) {
            if(decoded_data === null) {
                decoded_data = data;
            }
        }
        return decoded_data;
    }

    function isHTTPError(code) {
        return (code >= 400)? true : false;
    }

    // returns a done callback for our auth request
    function authReturn(done, fail) {
        return function(data, response) {

            var decoded_data = decodeOptionally(data),
                decoded_response = decodeOptionally(response);

            if(data === null) { fail(decoded_data, response); return; }

            if(isHTTPError(decoded_response.statusCode)) {
                fail(decoded_data, decoded_response);
                return;
            }

            if(typeof decoded_data.error !== "undefined") {
                fail(decoded_data, decoded_response);
                return;
            }
            // update our credential
            credential["access_token"] = decoded_data["access_token"];
            credential["token_expiration"] =
                         now() + (1000 * decoded_data["token_expiration"]);
            credential["token_type"] = decoded_data["token_type"];

            done(response);
            return;
        };
    }

    // returns a done callback for our json data request
    function jsonResponder(done, fail) {
        
        return function(data, response) {

            var decoded_data = decodeOptionally(data),
                decoded_response = decodeOptionally(response);

            if(isHTTPError(decoded_response.statusCode)) {

                fail(decoded_data, decoded_response);
                return;
            }
            // it could happen!
            if(decoded_data
            && typeof decoded_data.error !== "undefined") {

                fail(decoded_data, decoded_response);
                return;
            }

            done(decoded_data, decoded_response);
            return;
        };
    }

    function getProtocol() {
        
        return config['host_protocol'] + protocol_sep;
    }

    function getHostName(proto) {

        if(!proto) {
            
            return config["host_uri"];
        }

        return getProtocol() + config["host_uri"];
    }

    function auth(done, fail) {

        var reqpath = config['path_prefix'] + config["token_uri"],
            req = {
                hostname: getHostName(),
                hostport: config["host_port"],
                path: reqpath,
                method: "POST",
                type: "POST",
                access_token: credential["access_token"],
                body: getParamString(getAuthorizationParams(), true),
                url: getHostName(true) + reqpath
            };
        req.headers = shallowMerge( getAuthorizionHeader(req.body.length),
                                    getVersionHeader() );
        try {

            transportStrategy(req, authReturn(done, fail), fail);
        } catch(e) {
            
            fail(e);
        }

    }

    function getCredential(done, fail, flags) {

        // apiKey use precludes access to tokens
        if(credential['apiKey']) {
            fail();
            return;
        }
        // if we have a token and we can use it
        if (isValidToken()) {

            if(flags.hasOwnProperty("token_only")
            &&  flags["token_only"] === false) {

                if(flags.hasOwnProperty("public")
                && flags["public"] === true) {

                    shared_secret = credential.shared_secret;
                    shallowSubtract(private_credential,
                                    credential);
                }

                done(credential, null);
                return;
            }

            done(credential["access_token"]);
            return;
        }

        // auth has the side effect of setting
        // the credential's access token
        auth(
            function(response) {

                if(flags.hasOwnProperty("token_only")
                &&  flags["token_only"] === false) {

                    if(flags.hasOwnProperty("public")
                    && flags["public"] === true) {
                        shared_secret = credential.shared_secret;
                        shallowSubtract(private_credential,
                                        credential.shared_secret);
                    }

                    done(credential, response);
                    return;
                }
                
                done(credential["access_token"]);
                return;
            },
            fail
        );

    }

    function getRequestHeaders(done, fail) {
        
        var flags = shallowMerge(   {"token_only": true},
                                    default_credential_flags);
        if(credential['apiKey']) {
            
            done(getVersionHeader());
            return;
        } else {

            getCredential(function(access_token) {

                    var headers = shallowMerge( getAuthorizionHeader(),
                                                getVersionHeader() );
                    return done(headers);
                },
                fail,
                flags
            );
        }
    }

    function initDefaultConnectionParams() {

        default_params.getConnections = {
            "since": today() - (365 * milliseconds_in_a_day),
            "until": today(),
            "limit": 10
        };
    }

    function initCredential(cred) {
        
        clearCredential();
        credential = shallowMerge(cred, default_credential);
        has_credential = true;
    }

    function initConfig(user_config) {
        
        clearConfig();
        config = shallowMerge(
                    keySubset(allowed_config, user_config),
                    default_config);
    }

    function clearTransport() {
        
        transportStrategy = defaultTransportStrategy;
    }

    function initTransport(transport) {
        
        clearTransport();
        
        if(typeof transport === 'undefined') {

            if(node_env) {
                var path = require('path');
                transport = require(path.join(__dirname,'transport.js'));
            } else if (browser_env && bandpage_env) {
                transport = bandpage.sdk_transports.jsonp.makeRequest;
            } else {
                throw new Error("no default or user defined transports exist");
            }
        }
        transportStrategy = transport;
    }

    /**
     * we use the transport mechanism here
     * @param  {Object}     req  info given to the request mechanism
     * @param  {Function}   done how to get er dunn
     * @param  {Function}   fail how to fail
     * @return {undefined}
     */
    function executeRequest(req, done, fail) {

        req.hostname = getHostName();
        req.hostport = config["host_port"];
        req.access_token = credential["access_token"];
        req.client_id = credential["client_id"];
        var newpath = config['path_prefix'] + req.path;
        req.path = newpath;

        // go get the auth headers (which may include getting a token)
        getRequestHeaders(
            function(headers) {

                req.headers = headers;
                req.url = getHostName(true) + req.path;

                if(req.method === "GET") {
                
                    var paramstring = getParamString(req.params);
                    req.path += paramstring;

                    req.url += paramstring;
                    delete req.params;
                }
                try {
                
                    transportStrategy(req, jsonResponder(done, fail), fail);
                } catch(e) {
                
                    fail(e);
                }
            },
            fail
        );
    }

    function getLinkHeaders(headers) {
        var links = [],
            linkObj = {},
            linkObjects = [];

        for (var header in headers) {
            
            if (header.toLowerCase() === "link") {
            
                links.push(headers[header]);
            }
        }

        for(var link in links) {
            
            var arrayOrString = links[link];
            if(typeof arrayOrString !== 'string') {
            
                arrayOrString = arrayOrString[0];
            }
            var keys = arrayOrString.split(";");
            linkObj["link"] = keys.shift().slice(1, -1);
            for(var key in keys) {
            
                var parts = keys[key].split("=");
                linkObj[parts[0]] = parts[1].slice(1, -1);
            }
            linkObjects.push(linkObj);
        }

        return linkObjects;
    }

    /**
     * augments a function's done callback option to perform a
     * post process on the response augmenting with page functions
     * this should be decorated post-validation (an outer wrapper),
     * to ensure the existance of the done option we are wrapping
     *
     * @param  {Function}   fn function w/ variable args,
     *                      assumes last 2 args are done/fail callbacks
     * @return {Function}   function w/ same number of variable args,
     *                      done callback will execute with an
     *                      augmented response object
     */
    var pageable = exports.utility.registerDecorator('pageable', function pageable(fn) {

        return function() {

            var args = [].slice.call(arguments),
                userfail = args.pop(), // fail is last arg
                userdone = args.pop(); // done is second to last

            var preProcessedDone = function(data, response) {

                // get the link headers
                var linkObjects = getLinkHeaders(response.headers),
                    nextLink = null;

                function getNextPage(pageDone, pageFail) {

                    var pageableRequest =
                                new exports.utility.decorate(executeRequest, 'pageable'),
                        nextPageRequest = args[0],
                        nonPath = config.host_uri +
                                    config.path_prefix,
                        indexOfPath = nonPath.length + 1 +
                                nextLink.link.indexOf(nonPath);

                    // augment the request object
                    nextPageRequest.path = nextLink.link.slice(indexOfPath-1);
                    nextPageRequest.url = nextLink.link;
                    // add raw link object
                    nextPageRequest.nextLink = nextLink;

                    pageableRequest(nextPageRequest, pageDone, pageFail);
                    return;
                }

                // durfault behavior null
                response.getNextPage = null;

                for (var i in linkObjects) {

                    // find and set the next link
                    if(linkObjects[i].rel === "next") {
                    
                        nextLink = linkObjects[i];
                        response.nextLink = linkObjects[i];
                        // add getNextPage to the response object
                        response.getNextPage = getNextPage;
                    }
                    // find and set the prev link here..
                }

                // call original done
                userdone(data, response);
                return;
            };

            // execute original function, put our new done cb on the
            // call signature though
            fn.apply(fn, args.concat([preProcessedDone, userfail]));
        };
    });

    /**
     *  decorates and returns method which takes an options object
     *  checks for required options, filling in any provided defaults
     *  @param {Function} method - whose options must be validated
     *  @param {Array} required - set of required option keys
     *  @param {Object} defaults - optional key val pairs
     *  @throws error when lacking required options
     *  @returns {Function} a decorated
     */
    var requiresOptions = exports.utility.registerDecorator('requiresOptions',
        function requiresOptions(method, required, defaults) {

            if(!method) {
                
                throw new Error("No method given for requiresOptions method");
            }
            if(!required) {

                throw new Error("No options given for requiresOptions method");
            }
            return function(options) {

                var stillmissing = [],
                    missingkeys = getObjectMissingKeys(required, options);

                if(defaults && missingkeys && missingkeys.length > 0) {

                    for (var i=0, prop; prop = missingkeys[i++];) {

                        if(default_options.hasOwnProperty(prop)) {
                        
                            options[prop] = default_options[prop];
                        } else {
                        
                            stillmissing.push(prop);
                        }
                    }
                }

                if(stillmissing.length < 1) {

                    // call the wrapped method
                    method(options);
                    return;
                }

                // let the user know why we are breaking their script
                var msg = "Call to " + method.name
                        + " method is missing required options:";
                for (var j=0; j < stillmissing.length; j++) {

                    msg += " " + stillmissing[j];
                }
                throw new Error(msg);
                // I suppose we could..
                // options['fail']({},{'error': msg});
            };
        }
    );


    /**
     *  Public API
     */
    var api = {
        /**
         *  initialize a bandpage.api instance
         *  @param cred an object like credential
         *  @param user_config defaults that will be used for all methods
         *  @returns {undefined}
         */
        init: function init(cred, user_config) {
            
            if(!cred) throw new Error("Missing required init arguments");

            if(!user_config) user_config = {};

            updateTime();

            initCredential(cred);

            initConfig(user_config);

            initTransport(user_config["transport"]);

            initDefaultConnectionParams();

        },

        /**
         *  get the data of a specified bid
         *  @param   {Object} options - options object
         *  @throws  throws an error when lacking required options
         */
        get: exports.utility.decorate(function get( options ) {

                var request = {
                    method: "GET",
                    type: "GET",
                    path: config["get_uri"] + options.bid,
                    params: shallowMerge(
                                keySubset(allowed_params.get, options),
                                default_params.get)
                };

                executeRequest(request, options["done"], options["fail"]);
            },
            ["requiresOptions",
            required_options.get,
            default_options]
        ),

        /**
         *  retrives any kind of connections objects, supports paging
         *  via the getNextPage function in callback response object
         *  getNextPage will be null if there are no more pages of results
         *  @param   {Object} options - options object
         *  @throws  throws an error when lacking required options
         */
        getConnections: exports.utility.decorate(
            function getConnections( options ) {

                var pageableRequest = exports.utility.decorate( executeRequest, 'pageable'),
                    request = {
                        method: "GET",
                        type: "GET",
                        path: config["get_uri"] + options.bid + "/"
                            + options.connection_type,
                        params: shallowMerge(
                            keySubset(allowed_params.getConnections, options),
                            default_params.getConnections)
                    };

                pageableRequest(request, options["done"], options["fail"]);

            },
            ["requiresOptions",
            required_options.getConnections,
            default_options]
        )

    };

    exports.api = api;

})( ( typeof exports === "undefined" ) ? bandpage : exports );
