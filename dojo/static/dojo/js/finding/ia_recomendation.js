
// import { get_ia_recommendation, get_ia_recommendation2} from '../driver_adapter/ia_recommendation.js'; 

 function writingEffect(strings, elementId) {
    new TypeIt(elementId, {
        strings: strings,
        speed: 1,
        waitUntilVisible: true,
        cursor: false
    }).go();
}



 function FormaterHtmlRecommendation(recommendations){
    let html = "";
    html += `<h5>Recommendation</h5>`
    html += `<ul>`;
    recommendations.forEach(element => {
    html += `<li> ${element} </li>`
    });
    html += `</ul>`
    return html
}

 function FormaterHtmlMitigations(mitigations){
    let html = "";
    html += `<h5>Mitigations</h5>`;
    mitigations.forEach(element => {
        element = element.replace(/</g, '<;').replace(/>/g, '>;').replace(/&/g, '&amp;');
        html += `<pre><code class="language-css">${element}</code></pre>`;
    });
    return html
}

 function formaterHtmlFilesToFix(filesToFix){
    let html = "";
    html += `<h5>File To Fix</h5>`;
    html += `<ul>`;
    filesToFix.forEach(element => {
        html += `<li class="file-path" > ${element} </li>`;
    });
    html += `</ul>`;
    return html
}

function generarHtml(response){
    console.log(response)
    let htmlRecommendation =  FormaterHtmlRecommendation(response.data.recommendations)
    htmlRecommendation +=  FormaterHtmlMitigations(response.data.mitigations)
    htmlRecommendation +=  formaterHtmlFilesToFix(response.data.files_to_fix)
    return htmlRecommendation
}


function get_ia_recommendation(finding_id) {
    $.ajax({
        url: `https://09a7b3c2-0993-47f6-87ef-e7ec9e4c1f0d.mock.pstmn.io/open-assistant/marvin/tools/api/v1/devsecops/full-remediation-process/${finding_id}`,
        type: "GET",
        beforeSend: function() {
            $('#spinnerLoading').css('display', 'flex');
        },
        success: function(response) {
            let htmlRecomendation = generarHtml(response)
            writingEffect(htmlRecomendation, "#id_recommendation_content")
        },
        error: function(error) {
            console.log("erro or")
        },
        afeterSend: function() {
            $('#spinnerLoading').css('display', 'none');
        }
    });
}




$(document).ready(function() {
    $('#id_ia_recommendation').click(function(event)
    {
        get_ia_recommendation(1)
        // try {
        //     $('#spinnerLoading').css('display', 'flex');
        //     $('#id_ia_recommendation').prop('disabled', true);
        //     let response =  get_ia_recommendation(1)
        //     let htmlRecommendation =  FormaterHtmlRecommendation(response.data.recommendations)
        //     htmlRecommendation +=  FormaterHtmlMitigations(response.data.mitigations)
        //     htmlRecommendation +=  formaterHtmlFilesToFix(response.data.files_to_fix)
        //     writingEffect(htmlRecommendation, "#id_recommendation_content")
            
        // } catch (error) {
        //     console.error(error);
        // }
        // finally {
        //     console.log("Finally");
        //     $('#spinnerLoading').css('display', 'none');
        //     $('#id_ia_recommendation').prop('disabled', false);
        // }
    });
});
