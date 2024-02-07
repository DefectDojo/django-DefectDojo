$(document).ready(function() {
    $("#id_product_type_name").on("change", handleProductTypeChange);
});

$(document).ready(function() {
    $("#id_product_name").on("change", handleProductChange);
});

function handleProductChange(){
    let idProduct = $("#id_product_name").val();
    let engagementElement = document.getElementById('id_engagement_name');
    
    if (idProduct !== '') {
        getEngagementOptions(idProduct, engagementElement);
    } else {
        clearSelect(engagementElement);
    }
}

function getEngagementOptions(idProduct, engagementElement){
    $.ajax({
        url: "/api/v2/engagements/?product=" + idProduct,
        type: "GET",
        success: function(response) {
            console.log(response.results)
            clearSelect(engagementElement);
            addOption(engagementElement, '', 'Select Product Name...');
            response.results.forEach(function(engagement) {
                addOption(engagementElement, engagement.id, engagement.name);
            });
            refreshSelectPicker();
        },
        error: function(error) {
            console.error(error);
        }
    });
}

function handleProductTypeChange() {
    let idProductType = $("#id_product_type_name").val();
    let productTypeElement = document.getElementById('id_product_name');
    
    if (idProductType !== '') {
        getProductOptions(idProductType, productTypeElement);
    } else {
        clearSelect(productTypeElement);
    }
}

function getProductOptions(product_type_id, productTypeElement) {
    $.ajax({
        url: "/api/v2/products/?prod_type=" + product_type_id,
        type: "GET",
        success: function(response) {
            clearSelect(productTypeElement);
            addOption(productTypeElement, '', 'Select Product Type Name...');
            response.results.forEach(function(product) {
                addOption(productTypeElement, product.id, product.name);
            });
            refreshSelectPicker();
        },
        error: function(error) {
            console.error(error);
        }
    });
}

function clearSelect(select_element) {
    select_element.innerHTML = '';
    refreshSelectPicker();
}

function addOption(select_element, value, text) {
    select_element.innerHTML += `<option value='${value}'>${text}</option>`;
}

function refreshSelectPicker() {
    $('.selectpicker').selectpicker('refresh');
};