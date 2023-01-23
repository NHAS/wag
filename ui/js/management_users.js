

$(function () {
  let table = $('#userTable').DataTable({
    columns: [
      { 'data': "username" },
      { 'data': "data_added" },
      { 'data': "last_login" },
      { 'data': "ip" },
      { 'data': "locked" },
    ],
    order: [[0, 'asc']],
    select: true,

    ajax: "/settings/management_users/data",
  });
});
