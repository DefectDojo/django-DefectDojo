
import {setSessionStorage, getSessionStorage} from '../settings/session_storage.js'

export function FormaterHtmlRecommendation(data, elementId){
    new TypeIt(elementId, {
        strings: data["ia_recommendations"],
        speed: 1,
        waitUntilVisible: true,
        cursor: false,
        afterComplete: function () {
            $('#id_button_ia_recommendation').prop('disabled', false); 
            if(data["status"] == "Error"){
                $('#like_status').css('display', 'none');
            }
            else{
            $('#like_status').css('display', 'block');
            }
        }
    }).go();
}
