document.addEventListener('DOMContentLoaded', function () {
    let location = '/authorise/totp/';
    if (document.getElementById("registration") !== null) {
        location = "/register_mfa/totp/";
        populateTotpDetails()
    }

    document.getElementById('loginForm').onsubmit = function () {
        loginUser(location);
        return false;
    };
}, false);

async function populateTotpDetails() {
    const response = await fetch("/register_mfa/totp/", {
        method: 'GET',
        mode: 'same-origin',
        cache: 'no-cache',
        credentials: 'same-origin',
        redirect: 'follow'
    });

    if (response.ok) {

        let details;
        try {
            details = await response.json();
        } catch (e) {
            document.getElementById("error").hidden = false;
            return
        }

        document.getElementById("ImageData").src = details.ImageData;

        document.getElementById("AccountName").textContent = details.AccountName;
        document.getElementById("Key").textContent = details.Key;

    } else {
        document.getElementById("error").hidden = false;

        console.log("Unable to fetch TOTP details for registration: ", response.status, response.text);
    }
}

async function loginUser(location) {

    try {
        const send = await fetch(location, {
            method: 'POST',
            mode: 'same-origin',
            cache: 'no-cache',
            credentials: 'same-origin',
            redirect: 'follow',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
            },
            body: new URLSearchParams({
                "code": document.getElementById("mfaCode").value
            })
        });

        document.getElementById("mfaCode").value = "";

        if (!send.ok) {
            console.log("failed to send totp code")

            let response;
            try {
                response = await send.json();
            } catch (e) {
                console.log("logging in failed")

                document.getElementById("error").hidden = false;
                return
            }

            document.getElementById("errorMsg").textContent = response;
            document.getElementById("error").hidden = false;
            return
        }


        if (send.headers.get("WAG-CHALLENGE") !== null) {
            localStorage.setItem("challenge", send.headers.get("WAG-CHALLENGE"))
        }

    } catch (e) {
        console.log("logging in user failed")
        document.getElementById("errorMsg").textContent = e.message;
        document.getElementById("error").hidden = false;
        return
    }


    window.location.href = "/";
}