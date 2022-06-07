function logAjaxPost(url, data) {
    console.log('Sending Post Request to: ' + url + ' with data:\n' + JSON.stringify(data));
}

function logResponse(response) {
    console.log('Received the following response:\n');
    console.dir(response);
}

function logNavigatorCreate(parameter) {
    console.log('Calling navigator.credentials.create with parameter:\n' + JSON.stringify(parameter));
    console.log(`-> Browser looks for an Authenticator, requests access
                -> the User maybe needs to authenticate
                -> Browser pass the publicKey Options to the Authenticator
                -> Authenticator returns a credential or null if the options where incorrect`);
}

function logNavigatorGet(parameter) {
    console.log('Calling navigator.credentials.get with parameter:\n' + JSON.stringify(parameter));
}