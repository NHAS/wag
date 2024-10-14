

$(function () {
  createTable("#managementUsersTable", [
    {
      title: 'Username',
      field: 'username',
      align: 'center',
      sortable: true,
      escape: "true"
    }, {
      field: 'user_type',
      title: 'Type',
      sortable: true,
      align: 'center',
      escape: "true"
    },{
      field: 'date_added',
      title: 'Date Added',
      sortable: true,
      align: 'center',
      escape: "true"
    }, {
      field: 'last_login',
      title: 'Last Login',
      sortable: true,
      align: 'center',
      escape: "true"
    }, {
      field: 'ip',
      title: 'IP',
      sortable: true,
      align: 'center',
      escape: "true"
    }, {
      field: 'attempts',
      title: 'Login Attempts (>5 locked)',
      align: 'center',
      sortable: true,
      escape: "true"
    }, {
      field: 'change',
      title: 'Temp Password',
      align: 'center',
      sortable: true,
      escape: "true"
    }
  ])

})