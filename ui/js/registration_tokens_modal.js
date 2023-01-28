$("#createToken").on("click", function () {
    let data = {
        "username": $('#recipient-name').val(),
        "token": $('#token').val(),
        "overwrites": $('#overwrite').val(),
        "groups": $('#groups').val()
    }

    fetch("/management/registration_tokens/data", {
        method: 'POST',
        mode: 'same-origin',
        cache: 'no-cache',
        credentials: 'same-origin',
        redirect: 'follow',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    }).then((response) => {
        if (response.status == 200) {
            $("#tokensModal").modal("hide")
            table.bootstrapTable('refresh')
            return
        }

        response.text().then(txt => {

            $("#formIssue").text(txt)
            $("#formIssue").show()
        })
    })

})