'use strict';
$(document).ready(() => {
    if (!window.PublicKeyCredential) {
        alert("Error: this browser does not support WebAuthn");
    }
});

function base64ToUint8Array(base64Bytes) {
    const padding = '===='.substring(0, (4 - (base64Bytes.length % 4)) % 4);
    return base64js.toByteArray((base64Bytes + padding)
        .replace(/\//g, "_")
        .replace(/\+/g, "-"));
}

function uint8ArrayToBase64(bytes) {
    if (bytes instanceof Uint8Array) {
        return base64js.fromByteArray(bytes)
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=/g, "");
    }
    return uint8ArrayToBase64(new Uint8Array(bytes));

}

function parseResponse(response) {
    let credentialCreationOptions = "";
    if (typeof response === 'string') {
        credentialCreationOptions = JSON.parse(response);
    }
    return credentialCreationOptions;
}