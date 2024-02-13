var findingAcceptance = []


$(document).on('click', '.table-link', function(event) {
    event.preventDefault();
    let transferId = $(this).data('transfer-id');
    getTransferFindings(transferId)
});


$(document).ready(function() {
    $('#exampleModal').on('click', '.btn-success, .btn-warning, .btn-danger', function() {
        var btnClass = $(this).attr('class');
        var row = $(this).closest('tr');
        console.log(row)
        if (btnClass.includes('btn-success')) {
            row.find('.cls-finding-status').text("Transfer Accepted").css("color", "green");
        } else if (btnClass.includes('btn-warning')) {
            row.find('.cls-finding-status').text("Transfer Rejected").css("color", "#e7a100");
        } else if (btnClass.includes('btn-danger')) {
            row.find('.cls-finding-status').text("Transfer Removed").css("color", "red");
        }
    });
});

$(document).ready(function() {
    // Agregar controlador de eventos clic a los botones dentro de la tabla
    $('#risk_acceptance').on('click', '.btn-success, .btn-warning, .btn-danger', function() {
        var btnClass = $(this).attr('class');
        var row = $(this).closest('tr');
        console.log(row)
        if (btnClass.includes('btn-success')) {
            // Modificar el campo dentro de la fila para el botón de éxito
            row.find('.cls-transfer-finding-status').text("Transfer Accepted").css("color", "green");
        } else if (btnClass.includes('btn-warning')) {
            // Modificar el campo dentro de la fila para el botón de advertencia
            row.find('.cls-transfer-finding-status').text("Transfer Rejected").css("color", "#e7a100");
        } else if (btnClass.includes('btn-danger')) {
            // Modificar el campo dentro de la fila para el botón de peligro
            row.find('.cls-transfer-finding-status').text("Transfer Removed").css("color", "red");
        }

        // Realizar otras acciones según sea necesario
    });
});
function innerData(data){
    let tableBody = document.getElementById("id_data_transfer_finding")
    tableBody.innerHTML = ""
    data.results.forEach(function(transfer_finding_item){
        transfer_finding_item.finding_id.forEach(function(finding){
            let row = document.createElement("tr") 
            row.innerHTML = `
            <td>${finding.id}</td>
            <td>${finding.title}</td>
            <td>${finding.severity}</td>
            <td>${finding.cve}</td>
            <td class="cls-finding-status">${finding.risk_status}</td>
            <td><button type="button" class="btn btn-success btn-sm" data-btn-success=${finding.id}>
            <i class="fas fa-check"></i>
            </button>
            <button type="button" class="btn btn-warning btn-sm" data-btn-warning=${finding.id}>
            <i class="fas fa-times"></i>
            </button>
            <button type="button" class="btn btn-danger btn-sm" data-btn-danger=${finding.id}>
            <i class="fas fa-trash-alt"></i>
            </button></td>`; 
            tableBody.appendChild(row);
        });
    });
}


function getTransferFindings(transfer_findin_id){
    $.ajax({
        url: "/api/v2/transfer_finding?id=" + transfer_findin_id,
        type: "GET",
        success: function(response) {
            innerData(response)
            // response.results.forEach(function(transfer_finding_obj) {
            //     console.log(transfer_finding_obj);
        },
        error: function(error) {
            console.error(error);
        }
    });
}

function transfer_finding_acceptance(finding_id){

}