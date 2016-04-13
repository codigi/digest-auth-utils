var md5 = require("crypto-js/md5");

module.exports = {
    parseServerChallenge: function(header) {
        var splitting = header.split(', ');
        var challenge = {};

        for(var i=0; i<splitting.length; i++) {
            var values = /([a-zA-Z]+)=\"?([a-zA-Z0-9.@\/\s]+)\"?/.exec(splitting[i]);
            challenge[values[1]] = values[2];
        }

        return challenge;
    },

    generateRequestHeader: function(_nc, challenge, username, password, method, uri) {

        var nc = ("00000000"+_nc).slice(-8);

        /* Calculate cnonce */
        /* Math.randon().toString(36) -> "0.9g7hgvo99dj".slice(2) -> "9g7hgvo99dj" */
        var cnonce = ("00000000"+Math.random().toString(36).slice(2)).slice(-8);

        /* Calculate response MD5 */
        var ha1 = md5([username, challenge.realm, password].join(":"));
        var ha2 = md5([method, uri].join(":"));
        var response = md5([ha1, challenge.nonce, nc, cnonce, challenge.qop, ha2].join(":"));

        return "Digest " +
            "username=\""  + username            + "\", " +
            "realm=\""     + challenge.realm     + "\", " +
            "nonce=\""     + challenge.nonce     + "\", " +
            "uri=\""       + uri                 + "\", " +
            "algorithm=\"" + challenge.algorithm + "\", " +
            "response=\""  + response            + "\", " +
            "opaque=\""    + challenge.opaque    + "\", " +
            "qop=\""       + challenge.qop       + "\", " +
            "nc=\""        + nc                  + "\", " +
            "cnonce=\""    + cnonce              + "\"";
    }
};
