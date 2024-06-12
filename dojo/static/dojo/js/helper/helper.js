export function addOption(select_element, value, text) {
    select_element.innerHTML += `<option value='${value}'>${text}</option>`;
}


export function sleep(ms) {
    const start = new Date().getTime();
    while (new Date().getTime() < start + ms) {
    }
  }