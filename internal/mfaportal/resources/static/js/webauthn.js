document.addEventListener('DOMContentLoaded', function () {

    const registerButton = document.getElementById("registerButton");
    if (registerButton !== null) {
        registerButton.onclick = registerUser;
    }

    const loginButton = document.getElementById("loginButton");
    if (loginButton !== null) {
        loginButton.onclick = loginUser;
    }

    if (!window.PublicKeyCredential) {
        alert("Error: this browser does not support WebAuthn");
        return;
    }
}, false);

// Base64 to ArrayBuffer
function bufferDecode(value) {
    return Uint8Array.from(atob(value.replace(/_/g, '/').replace(/-/g, '+')), c => c.charCodeAt(0));
}

// ArrayBuffer to URLBase64
function bufferEncode(value) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}

async function registerUser(event) {
    if (event.target.disabled) {
        return
    }

    try {
        document.getElementById("registerButton").disable = true;

        const challenge = await fetch("/register_mfa/webauthn/", {
            method: 'GET',
            mode: 'same-origin',
            cache: 'no-cache',
            credentials: 'same-origin',
            redirect: 'follow'
        });

        if (!challenge.ok) {
            console.log("error getting challenge for registration: ", challenge.status)
            document.getElementById("error").hidden = false;
            return
        }

        let credentialCreationOptions;
        try {
            credentialCreationOptions = await challenge.json();
        } catch (e) {
            console.log("registering user failed")
            document.getElementById("error").hidden = false;
            return
        }

        credentialCreationOptions.publicKey.challenge = bufferDecode(credentialCreationOptions.publicKey.challenge);
        credentialCreationOptions.publicKey.user.id = bufferDecode(credentialCreationOptions.publicKey.user.id);
        if (credentialCreationOptions.publicKey.excludeCredentials) {
            for (var i = 0; i < credentialCreationOptions.publicKey.excludeCredentials.length; i++) {
                credentialCreationOptions.publicKey.excludeCredentials[i].id = bufferDecode(credentialCreationOptions.publicKey.excludeCredentials[i].id);
            }
        }

        const newCredential = await navigator.credentials.create({
            publicKey: credentialCreationOptions.publicKey
        });

        const attestationObject = newCredential.response.attestationObject;
        const clientDataJSON = newCredential.response.clientDataJSON;

        const body = JSON.stringify({
            id: newCredential.id,
            rawId: bufferEncode(newCredential.rawId),
            type: newCredential.type,
            response: {
                attestationObject: bufferEncode(attestationObject),
                clientDataJSON: bufferEncode(clientDataJSON),
            },
        })

        const finalise = await fetch('/register_mfa/webauthn/', {
            method: 'POST',
            mode: 'same-origin',
            cache: 'no-cache',
            credentials: 'same-origin',
            redirect: 'follow',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: body
        });

        if (!finalise.ok) {
            console.log("finalising registration failed")
            document.getElementById("error").hidden = false;
            return
        }
    } catch (e) {
        console.log("registering user failed")
        document.getElementById("errorMsg").textContent = e.message;
        document.getElementById("error").hidden = false;
        return
    } finally {
        document.getElementById("registerButton").disable = true;
    }

    window.location.href = "/";

}

async function loginUser(event) {
    if (event.target.disabled) {
        return
    }

    try {
        document.getElementById("loginButton").disable = true;

        const challenge = await fetch("/authorise/webauthn/", {
            method: 'GET',
            mode: 'same-origin',
            cache: 'no-cache',
            credentials: 'same-origin',
            redirect: 'follow'
        });

        if (!challenge.ok) {
            console.log("fetching login challenge failed")
            document.getElementById("error").hidden = false;
            return
        }

        let credentialRequestOptions;
        try {
            credentialRequestOptions = await challenge.json();
        } catch (e) {
            console.log("logging in failed: ", e)
            document.getElementById("error").hidden = false;
            return
        }

        credentialRequestOptions.publicKey.challenge = bufferDecode(credentialRequestOptions.publicKey.challenge);
        credentialRequestOptions.publicKey.allowCredentials.forEach(function (listItem) {
            listItem.id = bufferDecode(listItem.id);
        });

        let assertion;
        try {
            assertion = await navigator.credentials.get({
                publicKey: credentialRequestOptions.publicKey
            });
        } catch (e) {
            console.log("logging in failed: ", e)

            document.getElementById("errorMsg").textContent = e.message;
            if (e.name == "InvalidStateError") {
                document.getElementById("errorMsg").textContent = "Incorrect Security Device";
            }

            document.getElementById("error").hidden = false;
            return
        }


        let authData = assertion.response.authenticatorData;
        let clientDataJSON = assertion.response.clientDataJSON;
        let rawId = assertion.rawId;
        let sig = assertion.response.signature;
        let userHandle = assertion.response.userHandle;


        const body = JSON.stringify({
            id: assertion.id,
            rawId: bufferEncode(rawId),
            type: assertion.type,
            response: {
                authenticatorData: bufferEncode(authData),
                clientDataJSON: bufferEncode(clientDataJSON),
                signature: bufferEncode(sig),
                userHandle: bufferEncode(userHandle),
            },
        })

        const finalise = await fetch('/authorise/webauthn/', {
            method: 'POST',
            mode: 'same-origin',
            cache: 'no-cache',
            credentials: 'same-origin',
            redirect: 'follow',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: body
        });

        if (!finalise.ok) {

            let content = await finalise.json();

            console.log("logging in failed: ", content)

            document.getElementById("errorMsg").textContent = content;
            document.getElementById("error").hidden = false;

            return
        }
        
    } catch (e) {
        console.log("logging in failed: ", e)
        document.getElementById("errorMsg").textContent = e.message;
        document.getElementById("error").hidden = false;
        return
    } finally {
        document.getElementById("loginButton").disable = true;
    }


    window.location.href = "/";
}