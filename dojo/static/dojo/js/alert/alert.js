export function alertHide(alertClass){
    $(alertClass).alert().addClass('sr-only');
}

export function alertShow(alertClass){
    $(alertClass).alert().removeClass('sr-only');
}
