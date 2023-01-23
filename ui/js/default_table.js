function makeTable(tableID, columns, dataUrl, buttons, selector = ':not(.editor-select)') {

    columns.push({
        data: null,
        className: "dt-center editor-select",
        defaultContent: '<a href="#"><i class="fa fa-plus"/></a>',
        orderable: false
    })

    let table = $(tableID).DataTable({
        columns: columns,
        buttons: buttons,
        order: [[0, 'asc']],
        select: {
            style: 'os',
            selector: selector
        },

        ajax: dataUrl,
        dom: "<'row'<'col-lg-3'l><'col-lg-6'B><'col-lg-3'f>>" +
            "<'row'<'col-12'tr>>" +
            "<'row'<'col-5'i><'col-sm-7'p>>",
    });

    return table;
}