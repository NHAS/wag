$(function () {

    $(document).on('submit', '#generalSettings', function () {
        let data = {
            "HelpMail": $('#inputHelpMail').val(),
            "ExternalAddress": $('#inputWgAddress').val(),
            "DNS": $('#dns').val().split("\n").filter(element => element),
            "WireguardConfigFilename": $('#inputConfFileName').val(),
            "CheckUpdates": $("#checkUpdates").is(':checked')
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

        let selectMFAMethods = document.querySelectorAll('input[type="checkbox"].mfaselection:checked');

        // Create an empty array to store the values
        let checkedValues = [];
        selectMFAMethods.forEach(function (checkbox) {
            checkedValues.push(checkbox.value);
        });


        let data = {
            "MaxSessionLifetimeMinutes": parseInt($('#inputSessionLife').val()),
            "SessionInactivityTimeoutMinutes": parseInt($('#inputInactivity').val()),
            "Lockout": parseInt($('#numAttempts').val()),
            "DefaultMFAMethod": $('#defaultMFA').val(),
            "EnabledMFAMethods": checkedValues,
            "Domain": $('#inputVPNDomain').val(),


            "Issuer": $('#issuer').val(),
            "OidcDetails": {
                "IssuerURL": $('#oidcIssuerURL').val(),
                "ClientSecret": $('#oidcClientSecret').val(),
                "ClientID": $('#oidcClientID').val(),
                "GroupsClaimName": $('#oidcGroupsClaimName').val(),
                "DeviceUsernameClaim": $("#oidcDeviceUsernameClaim").val(),
                "Scopes": $('#oidcScopes').val().split("\n").filter(element => element),
            },
            "PamDetails": {
                "ServiceName": $('#pamServiceName').val(),
            }
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