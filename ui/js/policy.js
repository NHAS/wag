

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


$(function () {

  let table = createTable('#policyTable', [
    {
      field: 'state',
      checkbox: true,
      align: 'center',
    }, {
      title: 'Effects (Group/Username)',
      field: 'effects',
      align: 'center',
      sortable: true,
    }, {
      field: 'mfa_routes',
      title: 'MFA Routes (Number)',
      sortable: true,
      align: 'center'
    }, {
      field: 'public_routes',
      title: 'Public Routes (Number)',
      sortable: true,
      align: 'center'
    }
  ])

  var $remove = $('#remove')

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
      field: 'effects',
      values: ids
    })
    $remove.prop('disabled', true)
  })

});
