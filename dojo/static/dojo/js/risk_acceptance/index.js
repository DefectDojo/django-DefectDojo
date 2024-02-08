$(document).ready(function(){
    $(document).on("click", "#btn_accept_risk_reject", function(){
        updateModal("Reject","\n Are you sure to reject the finding?\n", "btn btn-warning", "confirmed_action_risk_pending", "id_modal_message")
        $('#confirmModal').modal('show');
    });

    $(document).on("click", "#btn_accept_risk_accept", function(){
        updateModal("Accept","\n Are you sure to Accept the finding?\n", "btn btn-success", "confirmed_action_risk_pending", "id_modal_message")
        $('#confirmModal').modal('show');
    });

    $(document).on("click", "#btn_accept_risk_remove", function(){
        updateModal("Remove","\n Are you sure to remove the finding?\n", "btn btn-danger", "confirmed_action_risk_pending", "id_modal_message")
        $('#confirmModal').modal('show');
    });

});

function updateModal(action, message, class_name, button_id, id_modal_message){
    buttonElement = document.getElementById(button_id);
    modalMessageElement = document.getElementById(id_modal_message);
    buttonElement.className = class_name;
    buttonElement.value = action;
    modalMessageElement.innerHTML = message;
}