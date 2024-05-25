$(document).ready(function() {
    $('.form-control-chosen').chosen();
});

export function get_engagements(product_id){
    return $.ajax({
        url: "/api/v2/products/" + product_id + "/engagements/",
        type: "GET",
        success: function(response) {
            console.log(response)
        },
        error: function(error) {
            console.log("error", error)
        }
    });
}

function update_list_finding_related(response){
}