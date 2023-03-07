

function getIdSelections(table) {
  return $.map(table.bootstrapTable('getSelections'), function (row) {
    return row.effects
  })
}

function responseHandler(res) {
  $.each(res.rows, function (i, row) {
    row.state = $.inArray(row.effects, selections) !== -1
  })
  return res
}

function operateFormatter(value, row, index) {
  return [
    '<a class="edit" href="javascript:void(0)" title="Edit">',
    '<i class="icon-pencil"></i>',
    '</a>  '
  ].join('')
}


window.operateEvents = {
  'click .edit': function (e, value, row, index) {
    $("#ruleModalLabel").text("Edit Rule")


    $("#effects").val(row.effects)
    $("#effects").prop("disabled", true)

    let mfa_routes_content = ""
    if (row.mfa_routes != null) {
      mfa_routes_content = row.mfa_routes.join("\n")
    }
    $("#mfa_routes").val(mfa_routes_content)

    let public_routes_content = ""
    if (row.public_routes != null) {
      public_routes_content = row.public_routes.join("\n")
    }
    $("#public_routes").val(public_routes_content)


    $("#action").val("edit")

    $("#ruleModal").modal("show")
  }
}

function rulesFormatter(values) {
  if (values == null) {
    return '0'
  }

  return values.length
}


$(function () {

  let table = createTable('#policiesTable', [
    {
      field: 'state',
      checkbox: true,
      align: 'center',
      escape: "true"
    }, {
      title: 'Effects (Group/Username)',
      field: 'effects',
      align: 'center',
      sortable: true,
      escape: "true"
    }, {
      field: 'mfa_routes',
      title: 'MFA Routes (Number)',
      sortable: true,
      align: 'center',
      formatter: rulesFormatter

    }, {
      field: 'public_routes',
      title: 'Public Routes (Number)',
      sortable: true,
      align: 'center',
      formatter: rulesFormatter

    }, {
      field: 'edit',
      title: 'Edit',
      align: 'center',
      clickToSelect: false,
      events: window.operateEvents,
      formatter: operateFormatter
    }
  ])

  var $remove = $('#remove')
  var $new = $('#new')
  var $save = $('#saveRule')

  $(".modal").on("hidden.bs.modal", function () {
    $("#formIssue").text("")
    $("#formIssue").hide()
    $("#action").val("")

  });


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
    table.bootstrapTable('remove', {
      field: 'effects',
      values: ids
    })

    fetch("/policy/rules/data", {
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
        $("#deleteModal").modal("hide")
        table.bootstrapTable('refresh')
        return
      }

      response.text().then(txt => {

        $("#deleteIssue").text(txt)
        $("#deleteIssue").show()
      })
    })

  })

  $new.on("click", function () {
    $("#ruleModalLabel").text("New Rule")

    $("#effects").prop("disabled", false)
    $("#effects").val("")

    $("#action").val("new")

    $("#mfa_routes").val("")
    $("#public_routes").val("")

    $("#ruleModal").modal("show")
  })

  $save.on("click", function () {
    let data = {
      "effects": $('#effects').val(),
      "mfa_routes": $('#mfa_routes').val().split("\n").filter(element => element),
      "public_routes": $('#public_routes').val().split("\n").filter(element => element),
    }

    let method = "POST";
    if ($('#action').val() == "edit") {
      method = "PUT"
    }

    fetch("/policy/rules/data", {
      method: method,
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
        $("#ruleModal").modal("hide")
        table.bootstrapTable('refresh')
        return
      }

      response.text().then(txt => {

        $("#formIssue").text(txt)
        $("#formIssue").show()
      })
    })
  })

});
