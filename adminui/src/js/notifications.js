




const httpsEnabled = window.location.protocol == "https:";
const url = (httpsEnabled ? 'wss://' : 'ws://') + window.location.host + "/notifications";

const template = document.querySelector("#notificationTemplate")

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
            y: 60,
            x: 10,
        },
        stopOnFocus: true,
        style: {
            background: msg.Color,
        }
    }).showToast();

    if (dropDownlist.querySelector("#" + msg.ID) != null) {
        // The event already exists in the notification
        return
    }

    /*
    <template id="notificationTemplate">
    <a class="notification dropdown-item d-flex align-items-center" id="external">
        <div>
            <div class="small text-gray-500" id="date"></div>
            <span class="font-weight-bold" id="heading"></span>

            <div id="message"></div>
        </div>
    </a>
    </template>
    */

    const clone = template.content.cloneNode(true);
    clone.querySelector("#date").textContent = msg.Time
    clone.querySelector("#heading").textContent = msg.Heading

    let messages = clone.querySelector("#message")

    for (let i = 0; i < msg.Message.length; i++) {
        let p = document.createElement("p")
        p.textContent = msg.Message[i]

        messages.appendChild(p)
    }

    dropDownlist.appendChild(clone);

    alertBadge.textContent = dropDownlist.querySelectorAll(".notification").length
    alertBadge.hidden = false
}


socket.onerror = function (err) {
    console.error('Socket encountered error: ', err.message, 'Closing socket');
    ws.close();
};
