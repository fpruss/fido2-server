'use strict';

function loginUser() {
    const username = $("#username").val()
    if (username === "") {
        alert("Please enter a username");
        return;
    }
    const url = '/login/begin';
    const data = {
        username: username
    };
    logAjaxPost(url, data)
    $.ajax({
            url: url,
            type: 'POST',
            data: data,
            datatype: 'json'
        }
    ).then((credentialRequestOptions) => {
        const credentialRequestOptionsJson = parseResponse(credentialRequestOptions);
        logResponse(credentialRequestOptionsJson);
        credentialRequestOptionsJson.publicKey.challenge = base64ToUint8Array(credentialRequestOptionsJson.publicKey.challenge);
        credentialRequestOptionsJson.publicKey.allowCredentials.forEach((credential) => {
            credential.id = base64ToUint8Array(credential.id);
        });
        logNavigatorGet(credentialRequestOptionsJson);
        return navigator.credentials.get({publicKey: credentialRequestOptionsJson.publicKey});
    }).then((assertion) => {
        logResponse(assertion);
        const encodedAssertion = {
            id: assertion.id,
            rawId: uint8ArrayToBase64(assertion.rawId),
            type: assertion.type,
            response: {
                authenticatorData: uint8ArrayToBase64(assertion.response.authenticatorData),
                clientDataJSON: uint8ArrayToBase64(assertion.response.clientDataJSON),
                signature: uint8ArrayToBase64(assertion.response.signature),
                userHandle: uint8ArrayToBase64(assertion.response.userHandle),
            },
        };
        const url = '/login/finish';
        const data = {
            credential: JSON.stringify(encodedAssertion),
            username: username
        };
        logAjaxPost(url, data)

        const params = {
            mode: "no-cors",
            headers: {
                "Content-Type": "application/json"
            },
            method: "POST",
            body: JSON.stringify(data)
        }

        fetch(url, params)
            .then((response) => {
                window.location.replace(response.url);
            }).catch((error) => {
            console.log(error)
            alert("failed to login " + username)
        })
    });
}

$('#loginButton').click(loginUser);