




const httpsEnabled = window.location.protocol == "https:";
const url = (httpsEnabled ? 'wss://' : 'ws://') + window.location.host + "/notifications";

let socket = new WebSocket(url)

const alertBadge = document.getElementById("numNotifications");
const dropDownlist = document.getElementById("notificationsDropDown");


if (dropDownlist.querySelectorAll(".notification").length > 0) {
    alertBadge.textContent = dropDownlist.querySelectorAll(".notification").length
    alertBadge.hidden = false
}

socket.onmessage = function (e) {
    const msg = JSON.parse(e.data)
    Toastify({
        text: msg.Message.join('\n'),
        className: "info",
        destination: msg.Url,
        newWindow: msg.OpenNewTab,
        position: "right",
        gravity: "top",
        offset: {
            y: 30,
        },
        stopOnFocus: true,
        style: {
            background: msg.Color,
        }
    }).showToast();
}


socket.onerror = function (err) {
    console.error('Socket encountered error: ', err.message, 'Closing socket');
    ws.close();
};
