'use strict';
function loginUser() {
    const form = document.getElementById('form');
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
        return {
            id: assertion.id,
            rawId: uint8ArrayToBase64(assertion.rawId),
            type: assertion.type,
            response: {
                authenticatorData: uint8ArrayToBase64(assertion.response.authenticatorData),
                clientDataJSON: uint8ArrayToBase64(assertion.response.clientDataJSON),
                signature: uint8ArrayToBase64(assertion.response.signature),
                userHandle: assertion.response.userHandle && uint8ArrayToBase64(assertion.response.userHandle),
            },
            clientExtensionResults: assertion.getClientExtensionResults(),
        };
    }).then((encodedResult) => {
        document.getElementById('credential').value = JSON.stringify(encodedResult);
        form.submit();
    }).catch((error) => {
        console.log(error)
        alert("failed to login")
    });
}

$('#loginButton').click(loginUser);
const element = document.getElementById('username');
element.addEventListener('keypress', (event) => {
    if (event.key === "Enter") {
        event.preventDefault();
    }
});