

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

function ownersFormatter(values, row) {
  let a = document.createElement('a')
  a.href = '/management/users/?username=' + encodeURIComponent(row.owner)
  a.innerText = row.owner

  return a.outerHTML
}

function lockedFormatter(value) {
  let p = document.createElement('span')
  if (value === true) {
    p.className = "badge badge-danger"
  }
  p.innerText = value
  return p.outerHTML
}


$(function () {
  let table = createTable('#devicesTable', [
    {
      field: 'state',
      checkbox: true,
      align: 'center',
      escape: "true"
    }, {
      title: 'Owner',
      field: 'owner',
      align: 'center',
      sortable: true,
      formatter: ownersFormatter
    }, {
      field: 'active',
      title: 'Active',
      sortable: true,
      align: 'center',
      escape: "true"
    }, {
      field: 'is_locked',
      title: 'Locked',
      sortable: true,
      align: 'center',
      formatter: lockedFormatter
    }, {
      field: 'internal_ip',
      title: 'Address',
      sortable: true,
      align: 'center',
      escape: "true"
    }, {
      field: 'public_key',
      title: 'Public Key',
      sortable: true,
      align: 'center',
      escape: "true"
    }, {
      field: 'last_endpoint',
      title: 'Last Endpoint Address',
      sortable: true,
      align: 'center',
      escape: "true"
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
        'Content-Type': 'application/json',
        'WAG-CSRF': $("#csrf_token").val()
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

  $('#clearFilter').on("click", function () {
    table.bootstrapTable('filterBy', {})
    $('#clearFilter').hide()
  })

  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.toString().length > 0) {
    $('#clearFilter').show()

    let filter = {}

    if (urlParams.has('owner')) {
      filter.owner = urlParams.get('owner')
    }

    if (urlParams.has('is_locked')) {
      filter.is_locked = urlParams.get('is_locked') == "true"
    }

    if (urlParams.has('active')) {
      filter.active = urlParams.get('active') == "true"
    }

    table.bootstrapTable('filterBy', filter)
  }

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
      'Content-Type': 'application/json',
      'WAG-CSRF': $("#csrf_token").val()
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