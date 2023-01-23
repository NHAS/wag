

// Call the dataTables jQuery plugin
$(function () {
  makeTable('#tokensTable',
    [
      { 'data': "token" },
      { 'data': "username" },
      { 'data': "groups" },
      { 'data': "overwrites" },

    ],
    "/management/registration_tokens/data",
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

    ],
  );
});
