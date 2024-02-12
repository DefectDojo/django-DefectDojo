window.onload = function(){
    element = document.getElementById('id_destination_product_type');
    element.selectedIndex = 0;
    element = document.getElementById('id_destination_product');
    element.selectedIndex = 0;
    element = document.getElementById('id_destination_engagement');
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
    $("#id_destination_product").on("change", handleProductChange);
});

function handleProductChange(){
    let idProduct = $("#id_destination_product").val();
    let engagementElement = document.getElementById('id_destination_engagement');
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
        url: "/api/v2/products/"+ idProduct +"/?prefetch=team_manager,technical_contact,product_manager",
        type: "GET",
        success: function(response) {
            clearSelect(contactsElement);
            addOption(contactsElement, '', 'Select Contact Product...');
            for(let key in response.prefetch){
                if(response.prefetch.hasOwnProperty(key)){
                    contactObj = getContact(response.prefetch[key]);
                    addOption(contactsElement, contactObj.id, contactObj.username)
                }
            }
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
    let productTypeElement = document.getElementById('id_destination_product');
    clearLabel()
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


function clearLabel(){
    element = document.getElementById('id_destination_product');
    element.selectedIndex = 0;
    element = document.getElementById('id_destination_engagement');
    element.selectedIndex = 0;
    element = document.getElementById('id_accepted_by');
    element.selectedIndex = 0;
    refreshSelectPicker();

}

$(document).on("submit", "form", function(event){
    console.log("init submint")
    try{
        let inputElement_product = document.getElementById('id_destination_product_name');
        let selectElement_product = document.getElementById('id_destination_product');
        let selectOption_product = selectElement_product.options[selectElement_product.selectedIndex];
        inputElement_product.value = selectOption_product.text

        let inputElement_accepted_by = document.getElementById('id_destination_accepted_by_name');
        let selectElement_accepted_by = document.getElementById('id_accepted_by');
        let selectOption_accpted_by = selectElement_accepted_by.options[selectElement_accepted_by.selectedIndex];
        inputElement_accepted_by.value = "este es toro nombre"

        let inputElement_engagement = document.getElementById('id_destination_engagement_name');
        let selectElement_engagement = document.getElementById('id_destination_engagement');
        let selectOption_engagement = selectElement_engagement.options[selectElement_engagement.selectedIndex];
        inputElement_engagement.value = "este es otro nombre"

        refreshSelectPicker();
    }catch(e){
        console.error(e.error)
    }

});