

// Call the dataTables jQuery plugin

$(function () {
  makeTable('#devicesTable',
    [
      { 'data': "owner" },
      { 'data': "is_locked" },
      { 'data': "internal_ip" },
      { 'data': "public_key" },
      { 'data': "last_endpoint" },
      { 'data': "last_handshake_time" },

    ],
    "/management/devices/data",
    [
      {
        text: '<i class="fas fa-lock fa-sm text-white-50 mr-2"></i>Lock',
        className: 'btn btn-primary shadow-sm',
        action: function (e, dt, node, config) {
          dt.ajax.reload();
        }
      },
      {
        text: '<i class="fas fa-unlock fa-sm text-white-50 mr-2"></i>Unlock',
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

    ]);
});
