// Shows nav elements marked `.auth-only` (e.g. the "Request a Quote" link)
// only once the visitor has signed in or created an account via login.html,
// which stores a token under `nd_token` in localStorage on success.
document.addEventListener('DOMContentLoaded', function () {
    if (localStorage.getItem('nd_token')) {
        document.querySelectorAll('.auth-only').forEach(function (el) {
            el.classList.remove('auth-only');
        });
    }
});
