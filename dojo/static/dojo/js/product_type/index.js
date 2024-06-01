window.onload = function(){
    element = document.getElementById('id_destination_product_type');
    element.selectedIndex = 0;
    element = document.getElementById('id_destination_product');
    element.selectedIndex = 0;
    element = document.getElementById('id_accepted_by');
    element.selectedIndex = 0;
}

$(document).ready(function() {
  $('#myModal').modal('show');
});

$(document).ready(function(){
    $("#id_destination_product").on("change", handleProductChange);
})
$(document).ready(function() {
    $("#id_destination_product_type").on("change", handleProductTypeChange);
});

function handleProductTypeChange(){
    let productTypeId = $("#id_destination_product_type").val()
    let  productElement = document.getElementById('id_destination_product') 
    console.log("productElementl",productElement)
    clearLabel("id_destination_product")
    clearLabel("id_accepted_by")
    getProductOptions(productTypeId, productElement)
    // traeer los productos relacioneado al producto type # TODO:
}
function handleProductChange(){
    let idProduct = $("#id_destination_product").val();
    let contactsElement = document.getElementById('id_accepted_by') 
    // let engagementElement = document.getElementById('id_destination_engagement');
    // clearLabel("id_destination_engagement");
    clearLabel("id_accepted_by");
    if (idProduct !== '') {
        getProductDescription(idProduct, contactsElement)
    } else {
        // clearSelect(engagementElement);
        clearSelect(contactsElement);
    }
}
function get_product_types_names(){
    $.ajax({
        url: "/products/type/names/",
        type: "GET",
        success: function(response) {
            response.results.forEach(function(product_type){
                clearSelect(contactsElement);
                // clearSelect(engagementElement);
                addOption(contactsElement, '', 'Select Contact Product_Type...');
                addOption(document.getElementById('id_destination_product_type'), product_type.id, product_type.name);
                // addOption(engagementElement, '', 'Select Engagement...');
            });
            refreshSelectPicker();
        },
        error: function(error) {
            console.error(error);
        }
    });
}
function getProductDescription(idProduct, contactsElement){
    $.ajax({
        url: "/product/type/description/" + idProduct,
        type: "GET",
        success: function(response) {
            clearSelect(contactsElement);
            // clearSelect(engagementElement);
            addOption(contactsElement, '', 'Select Contact Product...');
            contactsElement.innerHTML += `<option value=${response.contacts.product_manager.id}>${response.contacts.product_manager.username}</option>`;
            contactsElement.innerHTML += `<option value=${response.contacts.technical_contact.id}>${response.contacts.technical_contact.username}</option>`;
            contactsElement.innerHTML += `<option value=${response.contacts.team_manager.id}>${response.contacts.team_manager.username}</option>`;
            // addOption(engagementElement, '', 'Select Engagement...');
            // response.engagements.forEach(function(engagement){
            //     engagementElement.innerHTML += `<option value=${engagement.id}>${engagement.engagement_name}</option>`;
            // });

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

function getProductOptions(productTypeId, productElement){
    $.ajax({
        url: `/products/type/names/${productTypeId}`,
        type: "GET",
        success: function(response) {
            addOption(productElement, '', 'Select Product Name...');
            console.log(response)
            response.data.forEach(function(product) {
                addOption(productElement, product.id, product.name);
            });
            refreshSelectPicker();
        },
        error: function(error) {
            console.error(error);
        }
    });
}

function getEngagementOptions(idProduct, engagementElement){
    console.log("entro")
    $.ajax({
        url: "/api/v2/engagements/?product=" + idProduct,
        type: "GET",
        success: function(response) {
            clearSelect(engagementElement);
            addOption(engagementElement, '', 'Select Engagement Name...');
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
