function updateConfirmedModalByEvent(modal, titleMessageObject, bodyMessageObject){
    let action =  modal.data('tf-action')
    let bodyMessage = "Are you sure to perform this action?"
    let titleMessage = "Action Confirmed"
    let classButton = ""
    let colorButton = "#5cb85c"
    let textButton = "Confirmed"
    if(action == "Accepted"){
        bodyMessage = bodyMessageObject.accept
        titleMessage = titleMessageObject.accept
        classButton = "btn-success"
        colorButton = "#5cb85c"
        textButton = "Accept"
    }
    else if(action == "Rejected"){
        bodyMessage = bodyMessageObject.reject
        titleMessage = titleMessageObject.reject
        classButton = "btn-warning"
        colorButton = "#f0ad4e"
        textButton = "Reject"
    }
    else if(action == "Removed"){
        bodyMessage = bodyMessageObject.delete
        titleMessage = titleMessageObject.delete
        classButton = "btn-danger"
        colorButton = "#d9534f"
        textButton = "Delete"
    }
    modal.find('.modal-title').text(titleMessage)
    modal.find('.modal-body-input').text(bodyMessage)
    let confirmedActionModal = modal.find('#confirmed_action_modal')
    confirmedActionModal.css('background-color', colorButton);
    confirmedActionModal.val(textButton)
}

class MessageConfirmed {
    constructor(acceptMessage="", rejectMessage="", deleteMessage=""){
        this.accept = acceptMessage;
        this.reject = rejectMessage;
        this.delete = deleteMessage;
    }
}