import {MAX_RETRY, RETRY_INTERVAL} from '../settings.js';
export async function all(product_id)
{
    try
    {
        const response = await $.ajax({
            url: `/product/${product_id}/view_transfer_findings/all`,
            type: "GET",
            retry: MAX_RETRY,
            retryInterval: RETRY_INTERVAL,
        });

    return response;

    }catch(error){
        console.error(error);
        throw error;
    }
}