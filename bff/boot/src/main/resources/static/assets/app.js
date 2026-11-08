/*
 * Copyright (C) 2026 Alberto Irurueta Carro (alberto@irurueta.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// tag::bff-spa-js[]
const XSRF_COOKIE = 'XSRF-TOKEN';
const XSRF_PARAMETER = '_csrf';

/** Media types the documents API answers: its JSON results and its problem details. */
const JSON_OR_PROBLEM = 'application/json, application/problem+json';

/**
 * Finds an element of the page by its id.
 *
 * @param {string} id the id of the element.
 * @returns {HTMLElement} the element.
 */
const element = (id) => document.getElementById(id);

/**
 * Reads a cookie the script is allowed to see (the session cookie is HttpOnly and never visible).
 *
 * @param {string} name the name of the cookie.
 * @returns {string} the decoded value, or an empty string if the cookie is missing.
 */
const readCookie = (name) => {
    const prefix = `${name}=`;
    const entry = document.cookie.split('; ').find((cookie) => cookie.startsWith(prefix));
    return entry ? decodeURIComponent(entry.substring(prefix.length)) : '';
};

/**
 * Shows an error in the live region the screen readers announce, or clears it.
 *
 * @param {string} message the message, or an empty string to clear it.
 */
const showError = (message) => {
    const error = element('error');
    error.textContent = message;
    error.hidden = message === '';
};

/**
 * Sends the browser to the BFF login, asking to come back to the current page afterwards.
 */
const login = () => {
    const returnTo = window.location.pathname === '/index.html' ? '/index.html' : '/';
    window.location.assign(`/bff/login?returnTo=${encodeURIComponent(returnTo)}`);
};

/**
 * Shows the signed-out state, with the button that starts the sign-in. Nothing is started automatically: right after a
 * sign-out the authorization server sends the browser back here, and an automatic redirect would sign it in again.
 */
const showSignedOut = () => {
    element('status').textContent = 'You are signed out.';
    element('profile').hidden = true;
    element('documents').hidden = true;
    element('signed-out').hidden = false;
};

/**
 * Fills the profile card with the signed-in user.
 *
 * @param {{subject: string, name: string, email: string, roles: string[]}} user the user of the session.
 */
const showProfile = (user) => {
    element('profile-name').textContent = user.name ?? '';
    element('profile-email').textContent = user.email ?? '';
    element('profile-subject').textContent = user.subject ?? '';
    element('profile-roles').textContent = (user.roles ?? []).join(', ');
    element('status').textContent = `Signed in as ${user.name || user.subject}.`;
    element('profile').hidden = false;
};

/**
 * Renders the documents the API returned.
 *
 * @param {{id: string, title: string, content: string}[]} documents the documents.
 */
const showDocuments = (documents) => {
    const list = element('documents-list');
    list.replaceChildren(...documents.map((doc) => {
        const item = window.document.createElement('li');
        const title = window.document.createElement('strong');
        title.textContent = doc.title;
        item.append(title, `: ${doc.content}`);
        return item;
    }));
    element('documents-empty').hidden = documents.length > 0;
    element('documents').hidden = false;
};

/**
 * Asks the BFF for the user of the session, and shows the signed-out state when there is none.
 */
const loadUser = async () => {
    const response = await fetch('/bff/user', {credentials: 'same-origin', headers: {Accept: 'application/json'}});
    if (response.status === 401) {
        showSignedOut();
        return;
    }
    if (!response.ok) {
        throw new Error(`The session could not be read (${response.status}).`);
    }
    showProfile(await response.json());
};

/**
 * Loads the documents through the BFF, which asks the resource server with the access token of the user. A 401 here
 * means the session of a signed-in user has ended (or its token could not be renewed), so the sign-in starts again.
 */
const loadDocuments = async () => {
    showError('');
    // The BFF answers its failures as RFC 9457 problem details; asking for both types gets application/problem+json.
    const response = await fetch('/api/documents', {credentials: 'same-origin', headers: {Accept: JSON_OR_PROBLEM}});
    if (response.status === 401) {
        login();
        return;
    }
    if (!response.ok) {
        throw new Error(`The documents could not be loaded (${response.status}).`);
    }
    showDocuments(await response.json());
};

/**
 * Signs out with a top-level form POST, so that the browser itself follows the redirect of the BFF to the logout of the
 * authorization server: that URL carries the ID token hint, which a script must never read. A form cannot send a
 * header, so the CSRF token travels as the _csrf parameter.
 */
const signOut = () => {
    showError('');
    const form = window.document.createElement('form');
    form.method = 'post';
    form.action = '/bff/logout';
    form.hidden = true;
    const token = window.document.createElement('input');
    token.type = 'hidden';
    token.name = XSRF_PARAMETER;
    token.value = readCookie(XSRF_COOKIE);
    form.append(token);
    window.document.body.append(form);
    form.submit();
};

/**
 * Runs an action from a button, disabling it meanwhile and reporting a failure in the live region.
 *
 * @param {HTMLButtonElement} button the button that triggered the action.
 * @param {() => Promise<void>} action the action.
 */
const run = async (button, action) => {
    button.disabled = true;
    try {
        await action();
    } catch (error) {
        showError(error.message);
    } finally {
        button.disabled = false;
    }
};

const loadButton = element('load-documents');
const signOutButton = element('sign-out');
const signInButton = element('sign-in');
loadButton.addEventListener('click', () => run(loadButton, loadDocuments));
signOutButton.addEventListener('click', () => run(signOutButton, async () => signOut()));
signInButton.addEventListener('click', login);

// The heading takes the focus so a screen reader starts reading from the top of the page.
element('main-heading').focus();
if (new URLSearchParams(window.location.search).has('error')) {
    // The sign-in failed or was cancelled (for example, the consent was denied): say so instead of looping to the login.
    element('status').textContent = '';
    showError('Sign-in failed or was cancelled. No session was created.');
    element('retry').hidden = false;
} else {
    loadUser().catch((error) => {
        element('status').textContent = '';
        showError(error.message);
    });
}
// end::bff-spa-js[]
