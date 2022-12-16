document.addEventListener('DOMContentLoaded', function() {
    populateTotpDetails()
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
        const details = await response.json();

        document.getElementById("ImageData").src = details.ImageData;

        document.getElementById("AccountName").textContent = details.AccountName;
        document.getElementById("Key").textContent = details.Key;

    } else {
        document.getElementById("serverError").hidden = false;
        document.getElementById("mfaDisplay").hidden = true;

        console.log("Unable to fetch TOTP details for registration: ",  response.status, response.text);
    }
}