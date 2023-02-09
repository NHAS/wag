$(function () {

    $(document).on('submit', '#generalSettings', function () {

        return false;
    });

    $(document).on('submit', '#authSettings', function () {

        return false;
    });


    $(document).on('submit', '#loginSettings', function () {

        return false;
    });




    let oidcCheck = $('#oidc');
    let oidcSettings = $("#oidcSettings")
    oidcCheck.change(function () {
        if (oidcCheck.is(":checked")) {
            oidcSettings.show()
            return
        }
        oidcSettings.hide()
    });

})