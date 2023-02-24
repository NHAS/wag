

function getIdSelections(table) {
  return $.map(table.bootstrapTable('getSelections'), function (row) {
    return row.username
  })
}

function responseHandler(res) {
  $.each(res.rows, function (i, row) {
    row.state = $.inArray(row.username, selections) !== -1
  })
  return res
}

function devicesFormatter(value, row) {
  let a = document.createElement('a')
  a.href = '/management/devices/?owner=' + encodeURIComponent(row.username)
  a.innerText = value

  return a.outerHTML
}

function groupsFormatter(values) {

  let result = ""

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
  let table = createTable("#table", [
    {
      field: 'state',
      checkbox: true,
      align: 'center',
    }, {
      title: 'Username',
      field: 'username',
      align: 'center',
      sortable: true,
    }, {
      field: 'groups',
      title: 'Groups',
      sortable: true,
      align: 'center',
      formatter: groupsFormatter
    }, {
      field: 'devices',
      title: 'Devices',
      sortable: true,
      align: 'center',
      formatter: devicesFormatter
    }, {
      field: 'mfa_type',
      title: 'MFA Method',
      sortable: true,
      align: 'center'
    }, {
      field: 'enforcing_mfa',
      title: 'Enforcing MFA',
      sortable: true,
      align: 'center',
    }, {
      field: 'locked',
      title: 'Locked',
      align: 'center',
      sortable: true,
    }
  ])


  var $remove = $('#remove')
  var $lock = $('#lock')
  var $unlock = $('#unlock')
  var $resetMFA = $('#resetMFA')


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

  $unlock.on("click", function () {
    var ids = getIdSelections(table)
    action(ids, "resetMFA", table)
  })

  $remove.on("click", function () {
    var ids = getIdSelections(table)
    table.bootstrapTable('remove', {
      field: 'username',
      values: ids
    })

    fetch("/management/users/data", {
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

    if (urlParams.has('enforcing_mfa')) {
      filter.enforcing_mfa = urlParams.get('enforcing_mfa') == "true"
    }

    if (urlParams.has('username')) {
      filter.username = urlParams.get('username')
    }

    table.bootstrapTable('filterBy', filter)
  }

})


function action(onUsers, action, table) {
  let data = {
    "action": action,
    "usernames": onUsers,
  }

  fetch("/management/users/data", {
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