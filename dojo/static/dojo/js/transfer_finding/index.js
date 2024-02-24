var ObjFindings= {};
var transferId = 0;
var productId = 0;
var productTypeId = 0;

// Obtener el valor de la cookie 'csrftoken'
$(document).on('click', '.table-link', function(event) {
    event.preventDefault();
    transferId = $(this).data('transfer-id');
    productId = $(this).data('product-id');
    productTypeId = $(this).data('product-type-id');
    getTransferFindings(transferId, productId, productTypeId)
});


$(document).ready(function() {
    $('#exampleModal').on('click', '.btn-success, .btn-warning, .btn-danger', function() {
        var btnClass = $(this).attr('class');
        var row = $(this).closest('tr');
        if (btnClass.includes('btn-success')) {
            row.find('.cls-finding-status').text("Transfer Accepted").css("color", "green");
            let findingId = $(this).attr('data-btn-success');
            AcceptanceFinding(findingId)
        } else if (btnClass.includes('btn-warning')) {
            row.find('.cls-finding-status').text("Transfer Rejected").css("color", "#e7a100");
            let findingId = $(this).attr('data-btn-warning');
            RejectFinding(findingId)
        } else if (btnClass.includes('btn-danger')) {
            row.find('.cls-finding-status').text("Transfer Removed").css("color", "red");
            let findingId = $(this).attr('data-btn-danger');
            RemoveFinding(findingId)
        }
    });

$('#exampleModal').on('hidden.bs.modal', function () {
        // Limpiar las variables aquí
        variable1 = null;
        variable2 = null;
    });

   
});

$(document).ready(function() {
    $('#risk_acceptance').on('click', '.btn-success, .btn-warning, .btn-danger', function() {
        let btnClass = $(this).attr('class');
        let row = $(this).closest('tr');
        if (btnClass.includes('btn-success')) {
            row.find('.cls-transfer-finding-status').text("Transfer Accepted").css("color", "green");
            let findingId = $(this).attr('data-btn-success');
            AcceptanceFinding(findingId)
        } else if (btnClass.includes('btn-warning')) {
            row.find('.cls-transfer-finding-status').text("Transfer Rejected").css("color", "#e7a100");
            let findingId = $(this).attr('data-btn-warning');
            RejectFinding(findingId)
        } else if (btnClass.includes('btn-danger')) {
            row.find('.cls-transfer-finding-status').text("Transfer Removed").css("color", "red");
            let findingId = $(this).attr('data-btn-danger');
            RemoveFinding(findingId)
        }
    });
});

function AcceptanceFinding(findingId){
    ObjFindings[findingId] = {"risk_status": "Transfer Accepted"}
}
function RemoveFinding(findingId){
    ObjFindings[findingId] = {"risk_status": "Transfer Removed"}
}

function RejectFinding(findingId){
    ObjFindings[findingId] = {"risk_status": "Transfer Reject"}
}

Array.prototype.add = function(value){
    if (!this.includes(value)){
        this.push(value)
    }
    
}
Array.prototype.remove = function(value) {
    let index = this.indexOf(value);
    if (index !== -1) {
        this.splice(index, 1);
    }
};

function innerData(data){
    let tableBody = document.getElementById("id_data_transfer_finding")
    tableBody.innerHTML = ""
    data.results.forEach(function(transfer_finding_item){
        transfer_finding_item.findings.forEach(function(finding){
            let row = document.createElement("tr") 
            let cell_status = document.createElement("td")
            cell_status.className = "cls-finding-status"
            row.innerHTML = `
            <td>${finding.id}</td>
            <td>${finding.title}</td>
            <td>${finding.severity}</td>
            <td>${finding.cve}</td>`
            if(finding.risk_status.includes("Transfer Accepted")){
                cell_status.innerHTML= `<span style="color:green">Transfer Accepted</span>`
            }else if(finding.risk_status.includes("Transfer Reject")){
                cell_status.innerHTML = `<span style="color:#e7a100">Transfer Rejected</span>`
            }else{
                cell_status.innerHTML = `${finding.risk_status}`
            }
            row.appendChild(cell_status)
            row.innerHTML += `<td>
                ${transfer_finding_item.actions.includes(1216) && transfer_finding_item.actions.includes(1217)? 
                    `<button type="button" class="btn btn-success btn-sm" data-btn-success=${finding.id}>
                        <i class="fas fa-check"></i>
                     </button>
                     <button type="button" class="btn btn-warning btn-sm" data-btn-warning=${finding.id}>
                        <i class="fas fa-times"></i>
                     </button>`
                     :''}
                ${transfer_finding_item.actions.includes(1218) ? 
                    `<button type="button" class="btn btn-danger btn-sm" data-btn-danger=${finding.id}>
                        <i class="fas fa-trash-alt"></i>
                    </button>
                     `: ''}
            </td>`; 
            
            tableBody.appendChild(row);
        });
    });
}


function getTransferFindings(transfer_findin_id, productId, productTypeId){
    $.ajax({
        url: "/api/v2/transfer_finding?id=" + transfer_findin_id+'&'+"product="+productId+'&'+"product_type="+productTypeId,
        type: "GET",
        success: function(response) {
            innerData(response)
        },
        error: function(error) {
            console.error(error);
        }
    });
}


function filterForStatus(status){
    let ObjFindingsCopy = deepCopy(ObjFindings)
    for(let findingId in ObjFindingsCopy){
        if(!status.includes(ObjFindingsCopy[findingId].risk_status)){
            delete ObjFindingsCopy[findingId] 
        }
    }
    return ObjFindingsCopy
}

function deepCopy(objeto) {
    return JSON.parse(JSON.stringify(objeto));
}