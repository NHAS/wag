

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
    }, {
      field: 'last_handshake_time',
      title: 'Last Handshake Time',
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

      $remove.prop('disabled', enableModifications)
      $lock.prop('disabled', enableModifications)
      $unlock.prop('disabled', enableModifications)

      // save your data, here just save the current page
      selections = getIdSelections(table)
      // push or splice the selections if you want to save all data selections
    })

  $remove.on("click", function () {
    var ids = getIdSelections(table)
    table.bootstrapTable('remove', {
      field: 'internal_ip',
      values: ids
    })
    $remove.prop('disabled', true)
  })

});
