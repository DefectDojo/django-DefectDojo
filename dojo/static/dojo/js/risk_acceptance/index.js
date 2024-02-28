    $(document).ready(function(){
        var form = null;
        $(document).on("click", ".btn-warning", function(){
            form = $(this).closest('form');
            input = form.find('.action-tranfer-finding')
            input.attr('name', 'risk_accept_decline');
            updateModal("Reject","\n Are you sure to reject the finding?\n",
            "btn btn-warning",
            "#confirmed_action_risk_pending",
            "#id_modal_message")
            $('#confirmModal').modal('show');
        });

        $(document).on("click", ".btn-success", function(){
            form = $(this).closest('form');
            input = form.find('.action-tranfer-finding')
            input.attr('name', 'risk_accept_pending');
            updateModal("Accept",
            "\n Are you sure to Accept the finding?\n",
            "btn btn-success",
            "#confirmed_action_risk_pending",
            "#id_modal_message")
            $('#confirmModal').modal('show');
        });

        $(document).on("click", ".btn-danger", function(){
            form = $(this).closest('form');
            input = form.find('action-tranfer-finding')
            input.name = "remove_finding"
            updateModal("Remove",
            "\n Are you sure to remove the finding?\n",
            "btn btn-danger",
            "#confirmed_action_risk_pending",
            "#id_modal_message")
            $('#confirmModal').modal('show');
        });

        $(document).on('click','#confirmed_action_risk_pending', function(){
            form.submit();
        });

    });

    function updateModal(action, message, class_name, button, id_modal_message){
        buttonElement = document.getElementById(button);
        let modalMessageElement = document.getElementById(id_modal_message);
        buttonElement.addClass(class_name);
        buttonElement.val(action); 
        modalMessageElement.innerHTML = message;
    }