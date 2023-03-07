

function getIdSelections(table) {
  return $.map(table.bootstrapTable('getSelections'), function (row) {
    return row.group
  })
}

function responseHandler(res) {
  $.each(res.rows, function (i, row) {
    row.state = $.inArray(row.group, selections) !== -1
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
    $("#groupModalLabel").text("Edit Group")


    $("#group").val(row.group)
    $("#group").prop("disabled", true)

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
      escape: "true"
    }, {
      title: 'Group',
      field: 'group',
      align: 'center',
      sortable: true,
      escape: "true"
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
      field: 'group',
      values: ids
    })

    fetch("/policy/groups/data", {
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
    //Only pop up the modal which does the actual work
    $("#groupModalLabel").text("New Group")

    $("#group").prop("disabled", false)
    $("#group").val("")

    $("#action").val("new")

    $("#members").val("")

    $("#groupModal").modal("show")
  })

  $save.on("click", function () {
    /*
    type GroupData struct {
    Group   string   `json:"group"`
    Members []string `json:"members"`
    }
    */

    let currentGroupName = $('#group').val();

    let data = {
      "group": currentGroupName.startsWith("group:") ? currentGroupName : `group:${currentGroupName}`,
      "members": $('#members').val().split("\n").filter(element => element),
    }

    let method = "POST";
    if ($('#action').val() == "edit") {
      method = "PUT"
    }

    fetch("/policy/groups/data", {
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
        $("#groupModal").modal("hide")
        table.bootstrapTable('refresh')
        return
      }

      response.text().then(txt => {

        $("#formIssue").text(txt)
        $("#formIssue").show()
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

    if (urlParams.has('group')) {
      filter.group = urlParams.get('group')
    }

    table.bootstrapTable('filterBy', filter)
  }

});
