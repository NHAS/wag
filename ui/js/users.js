

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
        text: 'Delete',
        className: 'btn btn-danger shadow-sm',
        action: function (e, dt, node, config) {
          dt.ajax.reload();
        }
      },

    ]
  );
});
