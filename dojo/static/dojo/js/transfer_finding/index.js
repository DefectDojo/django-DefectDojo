import { get_product_with_description_findings } from '../product/index.js';
import { getSessionStorage, setSessionStorage } from '../settings/session_storage.js';
import {MAX_RETRY, RETRY_INTERVAL} from '../settings.js';
import { alertHide, alertShow } from '../alert/alert.js';
import { addOption, sleep} from '../helper/helper.js';

var ObjFindings= {};
export var transferId = 0;
export var productId = 0;
var productTypeId = 0;
var host = window.location.host;


$(document).ready(function(){
    $(document).on('click','.cls_transfer_finding_show_modal', function(event) {
        $('#spinnerLoading').css('display', 'flex');
        let row = $(this).closest('tr');
        transferId = $(this).data('transfer-id');
        $('.alert').alert().addClass('sr-only');
        let selectEngagement = row.find('.cls-choosen-engagement')
        let engagementId = selectEngagement.selectpicker('val');
        setSessionStorage("transferFinding", "engagementId", engagementId);
        $('#modalTransferFinding').modal('show');
        productId = $(this).data('product-id');
        setSessionStorage("transferFinding","productId",productId);
        productTypeId = $(this).data('product-type-id');
        getTransferFindings(transferId).then(function(event){
            $('#spinnerLoading').css('display', 'none');
        });
        $(document).on('change', '.related-finding-chosen', function(event){
            let selectedValue = $(this);
            let row = $(this).closest('tr');
            let finding = row.find('.btn-success');
            row.find('.label-primary').text("Transfer Pending").css("background", "#1371B6");
            let finding_id = finding.attr('data-btn-success');
            delete ObjFindings[finding_id];
            finding.attr('data-related-finding',selectedValue.val());
        });
    });
});


$(document).ready(function() {

    $('#modalTransferFinding').on('click', '.btn-success, .btn-warning, .btn-danger', function() {
        alertHide('.alert');
        let btnClass = $(this).attr('class');
        let row = $(this).closest('tr');
        if (btnClass.includes('btn-success'))
            {
                if (getSessionStorage('transferFinding','engagementId') !== "None"){
                    row.find('.label-primary').text("Transfer Accepted").css("background", "green");
                    let findingId = $(this).attr('data-btn-success');
                    let relatedFinding = $(this).attr('data-related-finding');
                    AcceptanceFinding(findingId, relatedFinding)
                }
                else
                {
                    alertShow('.alert');
                }
        } else if (btnClass.includes('btn-warning')) {
            row.find('.label-primary').text("Transfer Rejected").css("background", "#e7a100");
            let findingId = $(this).attr('data-btn-warning');
            RejectFinding(findingId)
        } else if (btnClass.includes('btn-danger')) {
            row.find('.label-primary').text("Transfer Removed").css("background", "red");
            let findingId = $(this).attr('data-btn-danger');
            RemoveFinding(findingId)
        }
    }); 
    
    $('#modalTransferFinding').on('hide.bs.modal', function(){
        ObjFindings = {};
    });

});


export async function getTransferFindingsAsync(transferFindingId) {
    try {
        const response = await $.ajax({
            url: `/api/v2/transfer_finding?id=${transferFindingId}`,
            type: 'GET',
            retry: MAX_RETRY,
            retryInterval: RETRY_INTERVAL,
        });
        return response;
    } catch (error) {
        throw error;
    }
}
function AcceptanceFinding(findingId, related_finding){
    if(related_finding == ""){
        ObjFindings[findingId] = {"risk_status": "Transfer Accepted"}
    }
    else{
        ObjFindings[findingId] = {"risk_status": "Transfer Accepted", "related_finding": related_finding}
    }
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


function innerData(data, findings_related){
    let tableBody = document.getElementById("id_data_transfer_finding")
    tableBody.innerHTML = ""
    data.results.forEach(function(transfer_finding_item){
        transfer_finding_item.transfer_findings.forEach(function(transfer_findings_finding){
            let row = document.createElement("tr") 
            let cell_status = document.createElement("td")
            cell_status.className = "cls-finding-status"

            row.innerHTML = `
            <td><a href="http://${host}/finding/${transfer_findings_finding.findings.id}/transfer_finding/${transfer_finding_item.id}", class="table-link cls-finding-id help help-toolpit" title="View Origin Finding" target="_blank" type="button">${transfer_findings_finding.findings.id} <i class="fa-solid fa-magnifying-glass-plus"></i> </a></td>
            <td class="cls-transfer-finding-title">${transfer_findings_finding.findings.title}</td>
            <td>${transfer_findings_finding.findings.severity}</td>
            <td>${transfer_findings_finding.findings.cve}</td>`
            if(["Transfer Accepted", "Transfer Expired"].includes(transfer_findings_finding.findings.risk_status)){
                row.innerHTML += `<td><a href="http://${host}/finding/${transfer_findings_finding.finding_related}" class="table-link help help-tooltip" title="View transfered finding" target="_blank" type="button"> ${transfer_findings_finding.finding_related} <i class="fa-solid fa-magnifying-glass-plus"></i> </a></td>`
                if(transfer_findings_finding.findings.risk_status.includes("Transfer Accepted")){
                    cell_status.innerHTML= `<span class="label label-primary" style="background: green">${transfer_findings_finding.findings.risk_status}</span>`
                }else{
                    cell_status.innerHTML= `<span class="label label-primary" style="background: #e7a100">${transfer_findings_finding.findings.risk_status}</span>`
                }
            }
            else if(transfer_findings_finding.findings.risk_status.includes("Transfer Reject"))
            {
                row.innerHTML += `${findings_related}`
                cell_status.innerHTML = `<span class="label label-primary" style="background: #e7a100">Transfer Rejected</span>`
            }
            else if(transfer_findings_finding.findings.risk_status.includes("Transfer Pending"))
            {
                row.innerHTML += `${findings_related}`
                cell_status.innerHTML = `<span class="label label-primary" style="background: #1371B6">Transfer Pending</span>`
            }
            else if(transfer_findings_finding.findings.risk_status.includes("Transfer Expired"))
            {
                row.innerHTML += `${findings_related}`
                cell_status.innerHTML = `<span class="label label-primary" style="background: #e7a100">Transfer Expired</span>`
            }
            else
            {
                row.innerHTML += `${findings_related}`
                cell_status.innerHTML = `${transfer_findings_finding.findings.risk_status}`
            }
            row.appendChild(cell_status)
            row.innerHTML += `<td>
                ${transfer_findings_finding.permission.includes(2805) && transfer_findings_finding.permission.includes(2806)? 
                    `<button type="button" class="btn btn-success btn-sm help help-tooltip" title="Accept Finding" data-btn-success=${transfer_findings_finding.findings.id} data-related-finding=""> 
                        <i class="fas fa-check"></i>
                    </button>
                    <button type="button" class="btn btn-warning btn-sm help help-tooltip" title="Reject Finding" data-btn-warning=${transfer_findings_finding.findings.id}>
                        <i class="fas fa-times"></i>
                    </button>`
                    :'--'}
                ${transfer_findings_finding.permission.includes(2807) ? 
                    `<button type="button" class="btn btn-danger btn-sm help help-tooltip" title="Delete Finding" data-btn-danger=${transfer_findings_finding.findings.id}>
                        <i class="fas fa-trash-alt"></i>
                    </button>
                    `: ''}
            </td>`; 
            tableBody.appendChild(row);
            $(".form-control-chosen").chosen();
        });
    });
}

function cleanData(data) {
    data.results.forEach(function(transfer_finding_item) {
        transfer_finding_item.transfer_findings = transfer_finding_item.transfer_findings.filter(function(transfer_findings_finding) {
            return transfer_findings_finding.findings !== null;
        });
    });
    return data;
}
    
async function getTransferFindings(transferFindingId){
    try
    {
        let related_findings = ""
        let transferFindingResponse = await getTransferFindingsAsync(transferFindingId);
        related_findings += `<td> <select class="form-control form-control-chosen related-finding-chosen" data-placeholder="Please select..."><option value=""> New Finding </option>`
        if (transferFindingResponse.results.length == 1)
            {
                const response = await get_product_with_description_findings(transferFindingResponse.results[0].destination_product);
                if(response.code === 200)
                {
                    for(let engagement of response.data.engagements_list)
                        {
                            if(engagement["id"] == getSessionStorage("transferFinding","engagementId"))
                            {
                                for(let finding of engagement.findings)
                                {
                                    related_findings += `<option class="help help-tooltip" title="${finding.title}" value="${finding.id}"> ${finding.id}</option>`;
                                }
                            }
                        }
                    related_findings += `</select></td>`;
                    transferFindingResponse = cleanData(transferFindingResponse);
                    innerData(transferFindingResponse, related_findings);
                }
                else
                {
                    transferFindingResponse = cleanData(transferFindingResponse);
                    innerData(transferFindingResponse, "<td>None</td>");
                }
            }
            else
            {
                throw new Error('A single value was expected for the transferFindingResponse variable', transferFindingResponse)
            }
    }
    catch(error){
        throw error;
    }
    
}

export function filterForStatus(status){
    let ObjFindingsCopy = deepCopy(ObjFindings)
    for(let findingId in ObjFindingsCopy){
        if(!status.includes(ObjFindingsCopy[findingId].risk_status)){
            delete ObjFindingsCopy[findingId] 
        }
    }
    return ObjFindingsCopy
}

export async function generateRequestTransferFindingUpdate(transferFindingId, riskStatus) {
    try {
        let requestFindingStatus = {};

        const response = await getTransferFindingsAsync(transferFindingId);
        response.results.forEach(function(transferFindings) {
            transferFindings.transfer_findings.forEach(function(finding) {
                requestFindingStatus[finding.findings.id] = {"risk_status": riskStatus};
            });
        });
        return requestFindingStatus;
    } catch (error) {
        throw error;
    }
}


function deepCopy(objeto) {
    return JSON.parse(JSON.stringify(objeto));
}
