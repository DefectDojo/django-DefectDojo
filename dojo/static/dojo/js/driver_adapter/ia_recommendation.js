import {MAX_RETRY, RETRY_INTERVAL} from '../settings.js';
export async function get_ia_recommendaton(finding_id)
{
    try
    {
        const response = await $.ajax({
            url: `https://09a7b3c2-0993-47f6-87ef-e7ec9e4c1f0d.mock.pstmn.io/open-assistant/marvin/tools/api/v1/devsecops/full-remediation-process/${finding_id}`,
            type: "GET",
        });

    return response;

    }catch(error){
        console.error(error);
        throw error;
    }
}