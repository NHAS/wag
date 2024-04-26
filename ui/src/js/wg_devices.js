

$(function () {
  createTable('#wgDevicesTable', [
    {
      title: 'Address',
      field: 'address',
      sortable: true,
      align: 'center',
      escape: "true",
    },
    {
      title: 'Public Key',
      field: 'public_key',
      align: 'center',
      sortable: true,
      escape: "true",
    }, {
      title: 'Endpoint Address',
      field: 'last_endpoint',
      sortable: true,
      align: 'center',
      escape: "true",
    }, {
      title: 'Recieved Bytes',
      field: 'rx',
      sortable: true,
      align: 'center',
      escape: "true",
    },
    {
      title: 'Sent Bytes',
      field: 'tx',
      sortable: true,
      align: 'center',
      escape: "true",
    },
    {
      title: 'Last Handshake Time',
      field: 'last_handshake_time',
      sortable: true,
      align: 'center',
      escape: "true",
    }
  ])
});