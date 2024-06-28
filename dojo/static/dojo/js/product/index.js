$(document).ready(function() {
    $('.form-control-chosen').chosen();
});

export async function get_product_with_description_findings(product_id){
    try{
        const response = await $.ajax({
            url: `/api/v2/products/${product_id}/engagements/`,
            type: "GET",
            error: function(error) {
                console.error(error)
            }
        });
        return response
    }
    catch (error){
        console.error(error)
        throw error
    }
}
