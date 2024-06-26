const acknowledgementButtons = document.querySelectorAll('.acknowledge');

acknowledgementButtons.forEach(el => el.addEventListener('click', event => {
    const errorid = event.target.getAttribute("errorid")

    fetch("/cluster/events/acknowledge", {
        method: 'POST',
        mode: 'same-origin',
        cache: 'no-cache',
        credentials: 'same-origin',
        redirect: 'follow',
        headers: {
            'Content-Type': 'application/json',
            'WAG-CSRF': $("#csrf_token").val()
        },
        body: JSON.stringify({ ErrorID: errorid })
    }).then((response) => {
        if (response.status !== 200) {
            response.text().then(txt => {
                console.log("failed to acknowledge error: ", txt)
                Toastify({
                    text: txt,
                    position: "right",
                    gravity: "bottom",
                    stopOnFocus: true,
                    style: {
                        background: "#db0b3c",
                    }
                }).showToast();
            })
            return
        }


        response.text().then(txt => {
            window.location.reload()

            Toastify({
                text: txt,
                className: "info",
                position: "right",
                gravity: "bottom",
                stopOnFocus: true,
                style: {
                    background: "#0bb329",
                }
            }).showToast();
        })
    })
}))
