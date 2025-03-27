
import {setSessionStorage, getSessionStorage} from '../settings/session_storage.js'

export function FormaterHtmlRecommendation(data, elementId){
    if (Array.isArray(data.recommendations) && data.recommendations.length > 0) {
        let html = "";
        html += `<h5>Recommendations</h5>`
        html += `<ul>`;
        data.recommendations.forEach(element => {
        html += `<li> ${element} </li>`
        });
        html += `</ul>`
        new TypeIt(elementId, {
            strings: html,
            speed: 1,
            waitUntilVisible: true,
            cursor: false,
            afterComplete: function () {
                FormaterHtmlMitigations(data, "#id_mitigations_contect")
            }
        }).go();

    }else{
        FormaterHtmlMitigations(data, "#id_recommendation_content")
    }
}

function FormaterHtmlMitigations(data, elementId){
    if (Array.isArray(data.mitigations) && data.mitigations.length > 0) {
        let html = "";
        html += `<h5>Mitigations</h5>`;
        data.mitigations.forEach(element => {
            let preElement = document.createElement("pre")
            let codeElement = document.createElement("code")
            codeElement.textContent = element
            preElement.appendChild(codeElement)
            html += preElement.outerHTML;
        });
        new TypeIt(elementId, {
            strings: html,
            speed: 1,
            waitUntilVisible: true,
            cursor: false,
            afterComplete: function () {
                formaterHtmlFilesToFix(data, "#id_files_to_fix_content")
            }
        }).go();
    }else{
        formaterHtmlFilesToFix(data, "#id_files_to_fix_content")
    }
}

function formaterHtmlFilesToFix(data, elementId){
    if (Array.isArray(data.files_to_fix) && data.files_to_fix.length > 0) {
        let html = "";
        html += `<h5>File To Fix</h5>`;
        html += `<ul>`;
        data.files_to_fix.forEach(element => {
            html += `<li class="file-path" > ${element} </li>`;
        });
        html += `</ul>`;
        new TypeIt(elementId, {
            strings: html,
            speed: 1,
            waitUntilVisible: true,
            cursor: false,
            afterComplete: function () {
                $('#spinnerLoading').css('display', 'none');
                $('#id_button_ia_recommendation').prop('disabled', false); 
            }
        }).go();
    }else{
        $('#spinnerLoading').css('display', 'none');
        $('#id_button_ia_recommendation').prop('disabled', false);
    }
}

