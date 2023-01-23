

// Call the dataTables jQuery plugin
$(function () {
  makeTable('#policyTable',

    [
      { 'data': "effects" },
      { 'data': "public_routes" },
      { 'data': "mfa_routes" },
      {
        data: null,
        className: "dt-center editor-edit",
        defaultContent: '<a href="#"><i class="fa fa-pen"/></a>',
        orderable: false
      },


    ],
    "/policy/rules/data",
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
