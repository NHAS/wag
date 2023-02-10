

$(function () {
  createTable("#managementUsersTable", [
    {
      title: 'Username',
      field: 'username',
      align: 'center',
      sortable: true,
    }, {
      field: 'date_added',
      title: 'Date Added',
      sortable: true,
      align: 'center'
    }, {
      field: 'last_login',
      title: 'Last Login',
      sortable: true,
      align: 'center'
    }, {
      field: 'ip',
      title: 'IP',
      sortable: true,
      align: 'center',
    }, {
      field: 'attempts',
      title: 'Login Attempts (>5 locked)',
      align: 'center',
      sortable: true,
    }
  ])

})