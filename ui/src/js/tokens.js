

function getIdSelections(table) {
  return $.map(table.bootstrapTable('getSelections'), function (row) {
    return row.token
  })
}

function responseHandler(res) {
  $.each(res.rows, function (i, row) {
    row.state = $.inArray(row.token, selections) !== -1
  })
  return res
}

function groupsFormatter(values) {

  if (values == null) {
    return "";
  }

  let result = ""
  console.log(values)
  values.forEach(function (e) {

    let a = document.createElement('a')
    a.className = "badge badge-primary"
    a.href = '/policy/groups/?group=' + encodeURIComponent(e)
    a.innerText = e


    result += a.outerHTML + "\n"
  });

  return result
}

$(function () {

  let table = createTable("#tokensTable", [
    {
      field: 'state',
      checkbox: true,
      align: 'center',
    }, {
      title: 'Token',
      field: 'token',
      align: 'center',
      sortable: true,
    }, {
      field: 'username',
      title: 'Username',
      sortable: true,
      align: 'center'
    }, {
      field: 'groups',
      title: 'Groups',
      sortable: true,
      align: 'center',
      formatter: groupsFormatter
    }, {
      field: 'overwrites',
      title: 'Overwrites',
      sortable: true,
      align: 'center',
    }
  ])


  var $remove = $('#remove')

  table.on('check.bs.table uncheck.bs.table ' +
    'check-all.bs.table uncheck-all.bs.table',
    function () {
      $("#removeStart").prop('disabled', !table.bootstrapTable('getSelections').length)

      // save your data, here just save the current page
      selections = getIdSelections(table)
      // push or splice the selections if you want to save all data selections
    })

  $remove.on("click", function () {
    var ids = getIdSelections(table)

    fetch("/management/registration_tokens/data", {
      method: "DELETE",
      mode: 'same-origin',
      cache: 'no-cache',
      credentials: 'same-origin',
      redirect: 'follow',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(ids)
    }).then(f => {
      table.bootstrapTable('remove', {
        field: 'token',
        values: ids
      })
    })
  })


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
        tokensTable.bootstrapTable('refresh')
        return
      }

      response.text().then(txt => {

        $("#formIssue").text(txt)
        $("#formIssue").show()
      })
    })

  })

  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.has("pop_modal")) {
    $("#tokensModal").modal("show")
  }


});
