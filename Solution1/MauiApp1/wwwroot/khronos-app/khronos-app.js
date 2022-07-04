export function getItemLocalStorage(key) {
    return localStorage.getItem(key);
}

export function setItemLocalStorage(key, value) {
    localStorage.setItem(key, value);
}

export function removeItemLocalStorage(key) {
    localStorage.removeItem(key);
}