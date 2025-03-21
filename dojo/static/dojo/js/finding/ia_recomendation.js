function FormaterHtmlRecommendation(data, elementId){
    let html = "";
    html += `<h5>Recommendation</h5>`
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
}

function FormaterHtmlMitigations(data, elementId){
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
}

function formaterHtmlFilesToFix(data, elementId){
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
}

export function get_ia_recommendation(finding_id, apiUrl) {
    $.ajax({
        url: `${apiUrl}/full-remediation-process/${finding_id}`,
        type: "GET",
        beforeSend: function() {
            $('#spinnerLoading').css('display', 'flex');
            $('#id_button_ia_recommendation').prop('disabled', true);
        },
        success: function(response) {
            FormaterHtmlRecommendation(response.data, "#id_recommendation_content")
        },
        error: function(error) {
            console.log(error)
        }
    });
}