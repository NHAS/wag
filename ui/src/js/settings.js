$(function () {

    $(document).on('submit', '#generalSettings', function () {
        let data = {
            "help_mail": $('#inputHelpMail').val(),
            "external_address": $('#inputWgAddress').val(),
            "dns": $('#dns').val().split("\n").filter(element => element)
        }

        fetch("/settings/general/data?type=general", {
            method: 'POST',
            mode: 'same-origin',
            cache: 'no-cache',
            credentials: 'same-origin',
            redirect: 'follow',
            headers: {
                'Content-Type': 'application/json',
                'WAG-CSRF': $("#csrf_token").val()
            },
            body: JSON.stringify(data)
        }).then((response) => {
            if (response.status == 200) {

                $("#generalSettingsIssue").text("Success!")
                $("#generalSettingsIssue").attr('class', "alert alert-success")
                $("#generalSettingsIssue").show()

                return
            }

            response.text().then(txt => {

                $("#generalSettingsIssue").text(txt)
                $("#generalSettingsIssue").attr('class', "alert alert-danger")
                $("#generalSettingsIssue").show()
            })
        })
        return false;
    });

    $(document).on('submit', '#loginSettings', function () {
        let data = {
            "session_lifetime": parseInt($('#inputSessionLife').val()),
            "session_inactivity": parseInt($('#inputInactivity').val()),
            "lockout": parseInt($('#numAttempts').val())
        }

        fetch("/settings/general/data?type=login", {
            method: 'POST',
            mode: 'same-origin',
            cache: 'no-cache',
            credentials: 'same-origin',
            redirect: 'follow',
            headers: {
                'Content-Type': 'application/json',
                'WAG-CSRF': $("#csrf_token").val()

            },
            body: JSON.stringify(data)
        }).then((response) => {
            if (response.status == 200) {

                $("#loginSettingsIssue").text("Success!")
                $("#loginSettingsIssue").attr('class', "alert alert-success")
                $("#loginSettingsIssue").show()

                return
            }

            response.text().then(txt => {

                $("#loginSettingsIssue").text(txt)
                $("#loginSettingsIssue").attr('class', "alert alert-danger")
                $("#loginSettingsIssue").show()
            })
        })

        return false;
    });
})