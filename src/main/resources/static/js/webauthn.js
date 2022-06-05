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

function registerUser() {
    const username = $('#username').val();
    if (username === '') {
        alert('please enter a username');
        return;
    }
    let displayName = $('#displayName').val();
    if (displayName === '') {
        displayName = username;
    }
    console.log('Sending Register User Ajax Request to the Server for user ' + username);
    $.ajax({
            url: '/register/begin',
            type: 'POST',
            data: {
                username: username,
                displayName: displayName
            },
            datatype: 'json'
        }
    ).then((credentialCreationOptions) => {
        const credentialCreationOptionsJson = parseResponse(credentialCreationOptions);
        return {
        publicKey: {
            ...credentialCreationOptionsJson.publicKey,
            challenge: base64ToUint8Array(credentialCreationOptionsJson.publicKey.challenge),
            user: {
                ...credentialCreationOptionsJson.publicKey.user,
                id: base64ToUint8Array(credentialCreationOptionsJson.publicKey.user.id),
            },
            excludeCredentials: credentialCreationOptionsJson.publicKey.excludeCredentials.map((credential) => ({
                ...credential,
                id: base64ToUint8Array(credential.id),
            })),
            extensions: credentialCreationOptionsJson.publicKey.extensions,
        },
    }}).then((credentialCreationOptions) => {
        console.log(`Calling navigator.credentials.create of the Credential Management API,
                -> Browser looks for an Authenticator, requests access
                -> the User maybe needs to authenticate
                -> Browser pass the publicKey Options to the Authenticator
                -> Authenticator returns a credential or null if the options where incorrect`);
        return navigator.credentials.create(credentialCreationOptions.publicKey)
    }).then((publicKeyCredential) => {
        console.log('The Authenticator returned: ');
        console.log(publicKeyCredential);
        console.log('The AuthenticatorAttestationResponse interface represents the authenticator\'s' +
            'response to a client’s request for the creation of a new public key credential.')
        console.log('It contains the public key, the Credential ID and a hash of the clientData, ' +
            'that represents the contextual binding of both the RP and the client. This includes the challenge.');
        return publicKeyCredential;
    }).then(publicKeyCredential => ({
        id: publicKeyCredential.id,
        rawId: uint8ArrayToBase64(publicKeyCredential.rawId),
        type: publicKeyCredential.type,
        response: {
            attestationObject: uint8ArrayToBase64(publicKeyCredential.response.attestationObject),
            clientDataJSON: uint8ArrayToBase64(publicKeyCredential.response.clientDataJSON),
        }
    })).then((encodedResult) => {

        $.ajax({
                url: '/register/finish',
                type: 'POST',
                data: {
                    credential: JSON.stringify(encodedResult),
                    username: username
                },
                datatype: 'json'
            }
        )
        // $.post(
        //     '/register/finish/' + username,
        //     JSON.stringify({
        //         id: credential.id,
        //         rawId: uint8ArrayToBase64(credential.rawId),
        //         type: credential.type,
        //         response: {
        //             attestationObject: uint8ArrayToBase64(credential.response.attestationObject),
        //             clientDataJSON: uint8ArrayToBase64(credential.response.clientDataJSON),
        //         },
        //     }),
        //     'json')
    }).then((response) => {
        if (response.status === 200) {
            window.location.href = response.url;
        } else {
            alert("failed to register " + username);
        }
    }).catch((error) => {
        console.log(error)
        alert("failed to register " + username)
    });
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