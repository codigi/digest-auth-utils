var digestUtils = require('digest-auth-utils');

var serverReply = 'WWW-Authenticate: Digest \
                          realm="testrealm@host.com",\
                          qop="auth,auth-int",\
                          nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",\
                          opaque="5ccc069c403ebaf9f0171e9517f40e41"';
console.log(serverReply);

var challenge = digestUtils.parseServerChallenge(serverReply);
console.log(challenge);

var authHeader = digestUtils.generateRequestHeader(1, challenge, "Mufasa", "Circle Of Life", "GET", "/dir/index.html");
console.log(authHeader);

