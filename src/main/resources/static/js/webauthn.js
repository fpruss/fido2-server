// import * as base64js from '/base64-js';
'use strict';
$(document).ready(function () {

    const browserSupportsWebAuthn = window.PublicKeyCredential;
    if (!browserSupportsWebAuthn) {
        alert("Error: this browser does not support WebAuthn");
    }
});

function base64ToUint8Array(base64Bytes) {
    const padding = '===='.substring(0, (4 - (base64Bytes.length % 4)) % 4);
    return base64js.toByteArray((base64Bytes + padding).replace(/\//g, "_").replace(/\+/g, "-"));
}

function uint8ArrayToBase64(bytes) {
    if (bytes instanceof Uint8Array) {
        return base64js.fromByteArray(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    } else {
        return uint8ArrayToBase64(new Uint8Array(bytes));
    }
}

function registerUser() {
    const username = $('#username').val();
    if (username === '') {
        alert('please enter a username');
        return;
    }
    let displayName = $('#displayName').val();
    if(displayName === '') {
        displayName = username;
    }
    console.log('Sending Register User Ajax Request to the Server for user ' + username);
    $.ajax({
            url: '/register',
            type: 'POST',
            data: { username: username, displayName : displayName} ,
            datatype: 'json'
        }
    ).then((response) => {
        const credentialCreationOptions = JSON.parse(response);
        console.log('The Server Response contains the following publicKeyCredentialCreationOptions:')
        console.log(credentialCreationOptions.publicKey)

        credentialCreationOptions.publicKey.challenge = base64ToUint8Array(credentialCreationOptions.publicKey.challenge);
        credentialCreationOptions.publicKey.user.id = base64ToUint8Array(credentialCreationOptions.publicKey.user.id);
        if (credentialCreationOptions.publicKey.excludeCredentials) {
            for (let i = 0; i < credentialCreationOptions.publicKey.excludeCredentials.length; i++) {
                credentialCreationOptions.publicKey.excludeCredentials[i].id = base64ToUint8Array(credentialCreationOptions.publicKey.excludeCredentials[i].id);
            }
        }
        console.log(`Calling navigator.credentials.create of the Credential Management API,
                -> Browser looks for an Authenticator, requests access
                -> the User maybe needs to authenticate
                -> Browser pass the publicKey Options to the Authenticator
                -> Authenticator returns a credential or null if the options where incorrect`);
        return navigator.credentials.create({
                publicKey: credentialCreationOptions.publicKey
            }
        ).then((credential) => {
                console.log('Authenticator returned: ');
                console.log(credential);
                console.log('The AuthenticatorAttestationResponse interface represents the authenticator\'s' +
                    'response to a client’s request for the creation of a new public key credential.')
                console.log('It contains the public key, the Credential ID and a hash of the clientData, ' +
                    'that represents the contextual binding of both the RP and the client. This includes the challenge.');
                $.post(
                    '/register/finish/' + username,
                    JSON.stringify({
                        id: credential.id,
                        rawId: uint8ArrayToBase64(credential.rawId),
                        type: credential.type,
                        response: {
                            attestationObject: uint8ArrayToBase64(credential.response.attestationObject),
                            clientDataJSON: uint8ArrayToBase64(credential.response.clientDataJSON),
                        },
                    }),
                    'json')
            }
        ).then(() => {
                alert("successfully registered " + username + "!")
            }
        ).catch((error) => {
            console.log(error)
            alert("failed to register " + username)
        })
    })
}

function loginUser() {

    const username = $("#username").val()
    if (username === "") {
        alert("Please enter a username");
        return;
    }

    $.get(
        '/login/begin/' + username,
        null,
        function (data) {
            return data
        },
        'json')
        .then((credentialRequestOptions) => {
            console.log(credentialRequestOptions)
            credentialRequestOptions.publicKey.challenge = base64ToUint8Array(credentialRequestOptions.publicKey.challenge);
            credentialRequestOptions.publicKey.allowCredentials.forEach(function (listItem) {
                listItem.id = base64ToUint8Array(listItem.id)
            });

            return navigator.credentials.get({
                publicKey: credentialRequestOptions.publicKey
            })
        })
        .then((assertion) => {
            console.log(assertion)
            let authData = assertion.response.authenticatorData;
            let clientDataJSON = assertion.response.clientDataJSON;
            let rawId = assertion.rawId;
            let sig = assertion.response.signature;
            let userHandle = assertion.response.userHandle;

            $.post(
                '/login/finish/' + username,
                JSON.stringify({
                    id: assertion.id,
                    rawId: uint8ArrayToBase64(rawId),
                    type: assertion.type,
                    response: {
                        authenticatorData: uint8ArrayToBase64(authData),
                        clientDataJSON: uint8ArrayToBase64(clientDataJSON),
                        signature: uint8ArrayToBase64(sig),
                        userHandle: uint8ArrayToBase64(userHandle),
                    },
                }),
                function (data) {
                    return data
                },
                'json')
        })
        .then(() => {
            alert("successfully logged in " + username + "!")
        })
        .catch((error) => {
            console.log(error)
            alert("failed to register " + username)
        })
}

$('#registerButton').click(registerUser);
$('#loginButton').click(loginUser);