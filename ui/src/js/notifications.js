const httpsEnabled = window.location.protocol == "https:";
const url = (httpsEnabled ? 'wss://' : 'ws://') + window.location.host + "/notifications";

var socket = new WebSocket(url)

const dropDownlist = document.getElementById("notificationsDropDown");

socket.onmessage = function (e) {
    const msg = JSON.parse(e.data)


}


socket.onerror = function (err) {
    console.error('Socket encountered error: ', err.message, 'Closing socket');
    ws.close();
};
