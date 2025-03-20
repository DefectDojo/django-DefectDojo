import {MAX_RETRY, RETRY_INTERVAL} from '../settings.js';
export function get_ia_recommendation(finding_id) {
    $.ajax({
        url: `https://09a7b3c2-0993-47f6-87ef-e7ec9e4c1f0d.mock.pstmn.io/open-assistant/marvin/tools/api/v1/devsecops/full-remediation-process/${finding_id}`,
        type: "GET",
        success: function(response) {
            return response
            console.log("print ok")
        },
        error: function(error) {
            console.log("erro or")
        }
    });
}

export function get_ia_recommendation2(finding_id) {
    return fetch(`https://09a7b3c2-0993-47f6-87ef-e7ec9e4c1f0d.mock.pstmn.io/open-assistant/marvin/tools/api/v1/devsecops/full-remediation-process/${finding_id}`)
        .then(response => response.json())  // Convierte la respuesta a JSON
        .then(data => {
            return data;  // Retorna los datos obtenidos
        })
        .catch(error => {
            console.error("Error al obtener la recomendación:", error);  // Maneja cualquier error
            throw error;  // Lanza el error nuevamente si quieres manejarlo fuera de la función
        });
}