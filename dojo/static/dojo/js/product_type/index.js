window.onload = function(){
    element = document.getElementById('id_destination_product');
    element.selectedIndex = 0;
    element = document.getElementById('id_accepted_by');
    element.selectedIndex = 0;
}

$(document).ready(function() {
  $('#myModal').modal('show');
});

$(document).ready(function() {
    $("#id_destination_product").on("change", handleProductChange);
});

function handleProductChange(){
    let idProduct = $("#id_destination_product").val();
    let contactsElement = document.getElementById('id_accepted_by') 
    clearLabel("id_accepted_by");
    if (idProduct !== '') {
        getContacs(idProduct, contactsElement)
    } else {
        clearSelect(engagementElement);
    }
}

function getContacs(idProduct, contactsElement){
    $.ajax({
        url: "/product/type/description/" + idProduct,
        type: "GET",
        success: function(response) {
            clearSelect(contactsElement);
            addOption(contactsElement, '', 'Select Contact Product...');
            response.products.forEach(function(product){
                contactsElement.innerHTML += `<option value=${product.contacts.product_manager.id}>${product.contacts.product_manager.username}</option>`;
                contactsElement.innerHTML += `<option value=${product.contacts.technical_contact.id}>${product.contacts.technical_contact.username}</option>`;
                contactsElement.innerHTML += `<option value=${product.contacts.team_manager.id}>${product.contacts.team_manager.username}</option>`;
            });
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


function clearLabel(id_element){
    try
    {
        element = document.getElementById(id_element);
        element.selectedIndex = 0;
        element.innerHTML = '';
        refreshSelectPicker();

    }
    catch(err) {
        console.error(err);
    }


}