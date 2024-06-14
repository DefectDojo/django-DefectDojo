export function setSessionStorage(module, key, value) {
    const prefixedKey = `${module}_${key}`;
    const serializedValue = JSON.stringify(value);
    sessionStorage.setItem(prefixedKey, serializedValue);
}

export function getSessionStorage(module, key) {
    const prefixedKey = `${module}_${key}`;
    const serializedValue = sessionStorage.getItem(prefixedKey);
    if (serializedValue) {
        return JSON.parse(serializedValue);
    }
    return null;
}
