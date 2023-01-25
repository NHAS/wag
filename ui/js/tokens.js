

// Call the dataTables jQuery plugin
$(function () {

  let table = makeTable('#tokensTable',
    [
      { 'data': "token" },
      { 'data': "username" },
      { 'data': "groups" },
      { 'data': "overwrites" },

    ],
    "/management/registration_tokens/data",
    [
      {

        text: '<i class="fas fa-plus fa-sm text-white-50 mr-2"></i>New',
        className: 'btn btn-primary shadow-sm',
        attr: {
          'data-toggle': 'modal',
          'data-target': '#tokensModal'
        }
      },
      {
        text: 'Select All',
        className: 'btn btn-primary shadow-sm',
        action: function () {
          table.rows().select();
        }
      },
      {
        text: 'Delete',
        className: 'btn btn-danger shadow-sm',
        action: function (e, dt) {
          var tokens = table.rows({ selected: true }).data().pluck('token').toArray();

          fetch("/management/registration_tokens/data", {
            method: "DELETE",
            mode: 'same-origin',
            cache: 'no-cache',
            credentials: 'same-origin',
            redirect: 'follow',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(tokens)
          }).then(f => {
            dt.ajax.reload();
          })

        }
      },

    ],
  );

  $("#createToken").click(function () {
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
        table.ajax.reload();
        return
      }

      response.text().then(txt => {
        console.log(txt)
        $("#formIssue").text(txt)
        $("#formIssue").show()
      })
    })

  })
});
