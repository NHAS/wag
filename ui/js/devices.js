

// Call the dataTables jQuery plugin
function getIdSelections(table) {
  return $.map(table.bootstrapTable('getSelections'), function (row) {
    return row.internal_ip
  })
}

function responseHandler(res) {
  $.each(res.rows, function (i, row) {
    row.state = $.inArray(row.internal_ip, selections) !== -1
  })
  return res
}


$(function () {
  let table = createTable('#devicesTable', [
    {
      field: 'state',
      checkbox: true,
      align: 'center',
    }, {
      title: 'Owner',
      field: 'owner',
      align: 'center',
      sortable: true,
    }, {
      field: 'is_locked',
      title: 'Locked',
      sortable: true,
      align: 'center'
    }, {
      field: 'internal_ip',
      title: 'Address',
      sortable: true,
      align: 'center'
    }, {
      field: 'public_key',
      title: 'Public Key',
      sortable: true,
      align: 'center'
    }, {
      field: 'last_endpoint',
      title: 'Last Endpoint Address',
      sortable: true,
      align: 'center'
    }
  ])

  var $remove = $('#remove')
  var $lock = $('#lock')
  var $unlock = $('#unlock')


  table.on('check.bs.table uncheck.bs.table ' +
    'check-all.bs.table uncheck-all.bs.table',
    function () {
      let enableModifications = !table.bootstrapTable('getSelections').length;

      $("#removeStart").prop('disabled', enableModifications)
      $lock.prop('disabled', enableModifications)
      $unlock.prop('disabled', enableModifications)

      // save your data, here just save the current page
      selections = getIdSelections(table)
      // push or splice the selections if you want to save all data selections
    })
  $lock.on("click", function () {
    var ids = getIdSelections(table)
    action(ids, "lock", table)
  })

  $unlock.on("click", function () {
    var ids = getIdSelections(table)
    action(ids, "unlock", table)
  })

  $remove.on("click", function () {
    var ids = getIdSelections(table)
    table.bootstrapTable('remove', {
      field: 'internal_ip',
      values: ids
    })


    fetch("/management/devices/data", {
      method: 'DELETE',
      mode: 'same-origin',
      cache: 'no-cache',
      credentials: 'same-origin',
      redirect: 'follow',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(ids)
    }).then((response) => {
      if (response.status == 200) {
        table.bootstrapTable('refresh')
        $("#issue").hide()
        return
      }

      response.text().then(txt => {

        $("#issue").text(txt)
        $("#issue").show()
      })
    })
  })

});

function action(onDevices, action, table) {
  let data = {
    "action": action,
    "addresses": onDevices,
  }

  fetch("/management/devices/data", {
    method: 'PUT',
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
      table.bootstrapTable('refresh')
      $("#issue").hide()
      return
    }

    response.text().then(txt => {
      $("#issue").text(txt)
      $("#issue").show()
    })
  })
}