

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
    '<i class="fa fa-pen"></i>',
    '</a>  '
  ].join('')
}


window.operateEvents = {
  'click .edit': function (e, value, row, index) {
    $("#groupModalLabel").text("Edit Group")


    $("#group").val(row.effects)
    $("#effects").prop("disabled", true)

    let members_content = ""
    if (row.members != null) {
      members_content = row.members.join("\n")
    }
    $("#members").val(members_content)

    $("#action").val("edit")

    $("#groupModal").modal("show")
  }
}

function membersFormatter(values) {
  if (values == null) {
    return '0'
  }

  return values.length
}


$(function () {

  let table = createTable('#groupsTable', [
    {
      field: 'state',
      checkbox: true,
      align: 'center',
    }, {
      title: 'Group',
      field: 'group',
      align: 'center',
      sortable: true,
    }, {
      title: 'Members (Number)',
      field: 'members',
      sortable: true,
      align: 'center',
      formatter: membersFormatter

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

  table.on('check.bs.table uncheck.bs.table ' +
    'check-all.bs.table uncheck-all.bs.table',
    function () {
      $remove.prop('disabled', !table.bootstrapTable('getSelections').length)

      // save your data, here just save the current page
      selections = getIdSelections(table)
      // push or splice the selections if you want to save all data selections
    })

  $remove.on("click", function () {
    var ids = getIdSelections(table)
    table.bootstrapTable('remove', {
      field: 'group',
      values: ids
    })
    $remove.prop('disabled', true)
  })

  $new.on("click", function () {
    $("#groupModalLabel").text("New Group")

    $("#group").prop("disabled", false)
    $("#group").val("")

    $("#action").val("new")

    $("#members").val("")

    $("#groupModal").modal("show")
  })

  $save.on("click", function () {
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
