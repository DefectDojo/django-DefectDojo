window.onload = function(){
    element = document.getElementById('id_destination_product_type');
    element.selectedIndex = 0;
    element = document.getElementById('id_destination_product_id');
    element.selectedIndex = 0;
    element = document.getElementById('id_destination_engagement_id');
    element.selectedIndex = 0;
    element = document.getElementById('id_accepted_by');
    element.selectedIndex = 0;
}
$(document).ready(function() {
    $("#id_destination_product_type").on("change", handleProductTypeChange);
});

$(document).ready(function() {
  $('#myModal').modal('show');
});

$(document).ready(function() {
    $("#id_destination_product_id").on("change", handleProductChange);
});

function handleProductChange(){
    let idProduct = $("#id_destination_product_id").val();
    let engagementElement = document.getElementById('id_destination_engagement_id');
    let contactsElement = document.getElementById('id_accepted_by') 
    
    if (idProduct !== '') {
        getEngagementOptions(idProduct, engagementElement);
        getContacs(idProduct, contactsElement)
    } else {
        clearSelect(engagementElement);
    }
}

function getContacs(idProduct, contactsElement){
    $.ajax({
        url: "/product/type/description/44",
        type: "GET",
        success: function(response) {
            console.log(response)
            clearSelect(contactsElement);
            addOption(contactsElement, '', 'Select Contact Product...');
            let contactObj = getContact(response.contacts);
            addOption(contactsElement, contactObj.id, contactObj.username)
            refreshSelectPicker();
        },
        error: function(error) {
            console.error(error);
        }
    });
}

function getContact(contact){
    let contactObj= Object.values(contact);
    return contactObj[0];
}

function getEngagementOptions(idProduct, engagementElement){
    $.ajax({
        url: "/api/v2/engagements/?product=" + idProduct,
        type: "GET",
        success: function(response) {
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
    let idProductType = $("#id_destination_product_type").val();
    let productTypeElement = document.getElementById('id_destination_product_id');
    clearLabel()
    if (idProductType !== '') {
        getTransferFindings(idProductType, productTypeElement);
    } else {
        clearSelect(productTypeElement);
    }
}

function getTransferFindings(product_type_id, productTypeElement) {
    $.ajax({
        url: "/product/type/description/" + product_type_id,
        type: "GET",
        success: function(response) {
            clearSelect(productTypeElement);
            addOption(productTypeElement, '', 'Select Product Type Name...');
            response.products.forEach(function(product) {
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


function clearLabel(){
    try
    {
        element = document.getElementById('id_destination_product_id');
        element.selectedIndex = 0;
        element = document.getElementById('id_destination_engagement_id');
        element.selectedIndex = 0;
        element = document.getElementById('id_accepted_by');
        element.selectedIndex = 0;
        refreshSelectPicker();

    }
    catch(err) {
        console.error(err);
    }


}