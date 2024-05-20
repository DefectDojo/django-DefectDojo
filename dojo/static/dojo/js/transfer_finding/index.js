var ObjFindings= {};
var transferId = 0;
var productId = 0;
var productTypeId = 0;
var host = window.location.host;
// Obtener el valor de la cookie 'csrftoken'
$(document).on('click', '#id_transfer_finding_show_modal', function(event) {
    event.preventDefault();
    transferId = $(this).data('transfer-id');
    productId = $(this).data('product-id');
    productTypeId = $(this).data('product-type-id');
    getTransferFindings(transferId, productId, productTypeId)
});


$(document).ready(function() {
    $('#modalTransferFinding').on('click', '.btn-success, .btn-warning, .btn-danger', function() {
        let btnClass = $(this).attr('class');
        let row = $(this).closest('tr');
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
});


function getTransferFindingsAsync(transferFindingId) {
    return new Promise(function(resolve, reject) {
        $.ajax({
            url: "/api/v2/transfer_finding?id=" + transferFindingId,
            type: "GET",
            success: function(response) {
                resolve(response);
            },
            error: function(error) {
                console.error(error);
                reject(error);
            }
        });
    });
}
function AcceptanceFinding(findingId){
    ObjFindings[findingId] = {"risk_status": "Transfer Accepted"}
}
function RemoveFinding(findingId){
    ObjFindings[findingId] = {"risk_status": "Transfer Removed"}
}

function RejectFinding(findingId){
    ObjFindings[findingId] = {"risk_status": "Transfer Rejected"}
}

function requestRiskStatusFinding(findingId, riskStatus){
    ObjFindings[findingId] = {"risk_status": riskStatus}
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
        transfer_finding_item.transfer_findings.forEach(function(findings){
            let row = document.createElement("tr") 
            let cell_status = document.createElement("td")
            cell_status.className = "cls-finding-status"
            row.innerHTML = `
            <td><a href="http://${host}/finding/${findings.findings.id}", class="table-link" target="_blank" type="button">${findings.findings.id}</a></td>
            <td>${findings.findings.title}</td>
            <td>${findings.findings.severity}</td>
            <td>${findings.findings.cve}</td>
            <td>
                <select id="is_valid" class="form-control form-control-chosen" data-placeholder="Please select...">
                  <option></option>
                  <option>None</option>
                </select>
            </div>
            </td>`
            if(findings.findings.risk_status.includes("Transfer Accepted")){
                cell_status.innerHTML= `<span style="color:green">Transfer Accepted</span>`
            }else if(findings.findings.risk_status.includes("Transfer Reject")){
                cell_status.innerHTML = `<span style="color:#e7a100">Transfer Rejected</span>`
            }else{
                cell_status.innerHTML = `${findings.findings.risk_status}`
            }
            row.appendChild(cell_status)
            row.innerHTML += `<td>
                ${transfer_finding_item.actions.includes(2801) && transfer_finding_item.actions.includes(2802)? 
                    `<button type="button" class="btn btn-success btn-sm" data-btn-success=${findings.findings.id}>
                        <i class="fas fa-check"></i>
                     </button>
                     <button type="button" class="btn btn-warning btn-sm" data-btn-warning=${findings.findings.id}>
                        <i class="fas fa-times"></i>
                     </button>`
                     :'--'}
                ${transfer_finding_item.actions.includes(2803) ? 
                    `<button type="button" class="btn btn-danger btn-sm" data-btn-danger=${findings.findings.id}>
                        <i class="fas fa-trash-alt"></i>
                    </button>
                     `: ''}
            </td>`; 
            
            tableBody.appendChild(row);
            $(".form-control-chosen").chosen();
        });
    });
}


function getTransferFindings(transfer_findin_id){
    $.ajax({
        url: "/api/v2/transfer_finding?id=" + transfer_findin_id,
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

function generateRequestTransferFindingUpdate(tranferFindingId, riskStatus){
    return new Promise(function(resolve, reject) {
        let requestFindingStatus = {};

        getTransferFindingsAsync(tranferFindingId)
            .then(function(response){
                response.results.forEach(function(transferFindings){
                    transferFindings.transfer_findings.forEach(function(finding){
                            requestFindingStatus[finding.findings.id] = {"risk_status": riskStatus};
                    });
                });
                resolve(requestFindingStatus);
            })
            .catch(function(error){
                console.error(error);
                reject(error);
            });
    });
}


function deepCopy(objeto) {
    return JSON.parse(JSON.stringify(objeto));
}

