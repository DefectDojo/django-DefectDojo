window.onload = function(){
    element = document.getElementById('id_product_type_id');
    element.selectedIndex = 0;
    element = document.getElementById('id_product_name');
    element.selectedIndex = 0;
    element = document.getElementById('id_engagement_name');
    element.selectedIndex = 0;
    element = document.getElementById('id_accepted_by');
    element.selectedIndex = 0;
}
$(document).ready(function() {
    $("#id_product_type_id").on("change", handleProductTypeChange);
});

$(document).ready(function() {
  $('#myModal').modal('show');
});

$(document).ready(function() {
    $("#id_product_name").on("change", handleProductChange);
});

function handleProductChange(){
    let idProduct = $("#id_product_name").val();
    let engagementElement = document.getElementById('id_engagement_name');
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
                    console.log("key");
                    console.log(key);
                    console.log("value");
                    console.log(response.prefetch[key]);
                    console.log("object value");
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
    console.log("que paso")
    let idProductType = $("#id_product_type_id").val();
    let productTypeElement = document.getElementById('id_product_name');
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
    element = document.getElementById('id_product_name');
    element.selectedIndex = 0;
    element = document.getElementById('id_engagement_name');
    element.selectedIndex = 0;
    element = document.getElementById('id_accepted_by');
    element.selectedIndex = 0;
    refreshSelectPicker();

}