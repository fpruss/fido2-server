'use strict';

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
    const url = '/register/begin';
    const data = {
        username: username,
        displayName: displayName
    };
    logAjaxPost(url, data)
    $.ajax({
            url: url,
            type: 'POST',
            data: data,
            datatype: 'json'
        }
    ).then((credentialCreationOptions) => {
        const credentialCreationOptionsJson = parseResponse(credentialCreationOptions);
        logResponse(credentialCreationOptionsJson);
        credentialCreationOptionsJson.publicKey.challenge = base64ToUint8Array(credentialCreationOptionsJson.publicKey.challenge);
        credentialCreationOptionsJson.publicKey.user.id = base64ToUint8Array(credentialCreationOptionsJson.publicKey.user.id);
        credentialCreationOptionsJson.publicKey.excludeCredentials.forEach((credential) => {
            credential.id = base64ToUint8Array(credential.id)
        });
        logNavigatorCreate(credentialCreationOptionsJson);
        return navigator.credentials.create({publicKey: credentialCreationOptionsJson.publicKey});
    }).then((publicKeyCredential) => {
        logResponse(publicKeyCredential);
        const encodedResult = {
            id: publicKeyCredential.id,
            rawId: uint8ArrayToBase64(publicKeyCredential.rawId),
            type: publicKeyCredential.type,
            response: {
                attestationObject: uint8ArrayToBase64(publicKeyCredential.response.attestationObject),
                clientDataJSON: uint8ArrayToBase64(publicKeyCredential.response.clientDataJSON),
            },
            clientExtensionResults: publicKeyCredential.getClientExtensionResults()
        };
        const url = '/register/finish';
        const data = {
            credential: JSON.stringify(encodedResult),
            username: username
        };
        logAjaxPost(url, data);

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
            alert("failed to register " + username)
        })
    });
}

$('#registerButton').click(registerUser);