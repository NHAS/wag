
var selections = []

function createTable(tableName, columns) {
    let table = $(tableName);
    table.bootstrapTable('destroy').bootstrapTable({
        locale: "en-US",
        columns: columns,
    })

    return table
}

