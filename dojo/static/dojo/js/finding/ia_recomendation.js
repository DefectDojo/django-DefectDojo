
import { get_ia_recommendaton } from '../driver_adapter/ia_recommendation.js'; 

function writingEffect(text, elementId) {
    let arrFromStr = text.split('');
    let i = 0;
    let element = document.getElementById(elementId);
    element.innerHTML = '';

    let printStr = setInterval(function() {
        if (arrFromStr[i] === ' ') {
            element.innerHTML += ' ';
            i++;
        } else {
            element.innerHTML += arrFromStr[i];
            i++;
        }

        if (i === arrFromStr.length) {
            clearInterval(printStr);
            element.style.color = "steelblue";
        }
    }, 50); 
}



$(document).ready(function() {
    $('#id_ia_recommendation').click(async function(event) {
       let response = await get_ia_recommendaton(1)
       const panelBody = document.querySelector('#ia_recommendation');
       panelBody.innerHTML = "";
       let recommendations = ``; 
       response.data.recommendations.forEach(element => {
              recommendations += `${element}`; 
       });
       console.log(recommendations);
       writingEffect(recommendations, "ia_recommendation")

    });
});
