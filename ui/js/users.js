

// Call the dataTables jQuery plugin
$(function () {
  makeTable('#userTable',
    [
      { 'data': "username" },
      { 'data': "groups" },
      { 'data': "devices" },
      { 'data': "enforcing_mfa" },
      { 'data': "locked" },
      { 'data': "date_added" },


    ],
    "/management/users/data",
    [
      {
        text: '<i class="fas fa-plus fa-sm text-white-50 mr-2"></i>New',
        className: 'btn btn-primary shadow-sm',
        action: function (e, dt, node, config) {
          dt.ajax.reload();
        }
      },
      {
        text: 'Delete',
        className: 'btn btn-danger shadow-sm',
        action: function (e, dt, node, config) {
          dt.ajax.reload();
        }
      },

    ]
  );
});
