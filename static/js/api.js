function getCookie(cookieName) {
    let cookie = {};
    document.cookie.split(';').forEach(function (el) {
        let [key, value] = el.split('=');
        cookie[key.trim()] = value;
    })
    return cookie[cookieName];
}

function getToken() {
    return getCookie('token');
}

function apiFetch(apiUrl) {
    let url = `${document.location.protocol}//${document.location.host}/api/${apiUrl}`;
    console.log(url)
    return fetch(url, {
        headers: {
            'Authorization': `Token ${getToken()}`
        }
    })
        .then((response) => {
            return response.json().then((data) => {
                return data;
            })
        });
}

