

$(function () {
  createTable('#wgDevicesTable', [
    {
      title: 'Address',
      field: 'address',
      sortable: true,
      align: 'center'
    },
    {
      title: 'Public Key',
      field: 'public_key',
      align: 'center',
      sortable: true,
    }, {
      title: 'Endpoint Address',
      field: 'last_endpoint',
      sortable: true,
      align: 'center'
    }, {
      title: 'Last Handshake Time',
      field: 'last_handshake_time',
      sortable: true,
      align: 'center'
    }
  ])
});