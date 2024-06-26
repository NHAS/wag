
const httpsEnabled = window.location.protocol == "https:";
const url = (httpsEnabled ? 'wss://' : 'ws://') + window.location.host + "/challenge/";

let backoff = 200;
let challenge = localStorage.getItem("challenge");
if (challenge === null || challenge === "null") {
    // oidc sets the challenge via cookie
    challenge = getCookie("challenge");
    if(challenge !== null) {
        localStorage.setItem("challenge", challenge)
    }
    deleteCookie("challenge")
}

function connect() {

    let ws = new WebSocket(url);
    ws.onopen = function () {
        ws.send(
            JSON.stringify({challenge: challenge
        }));
    };

    ws.onmessage = function (e) {
        backoff = 200
        console.log('Message:', e.data);

        let msg = JSON.parse(e.data)
        switch(msg) {
            case "challenge":
                ws.send(
                    JSON.stringify({challenge: challenge
                }));
            return
            case "reset":
                localStorage.removeItem("challenge")
                window.location.href = '/'
            return
        }
   
    };

    ws.onclose = function (e) {
        console.log(`Socket is closed. Reconnect will be attempted in ${backoff} ms.`, e.reason);
        if(backoff < 1000) {
            backoff += backoff*2
        }
        setTimeout(function () {
            connect();
        }, backoff);
    };

    ws.onerror = function (err) {
        console.error('Socket encountered error: ', err.message, 'Closing socket');
        ws.close();
    };
}

function getCookie(name) {
    function escape(s) { return s.replace(/([.*+?\^$(){}|\[\]\/\\])/g, '\\$1'); }
    var match = document.cookie.match(RegExp('(?:^|;\\s*)' + escape(name) + '=([^;]*)'));
    return match ? match[1] : null;
}

function deleteCookie(name) {
    document.cookie = name +'=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
  }


if(challenge !== null) {
    connect();
} else {
    console.log("unable to get challenge, will not start websockets connection")
}
