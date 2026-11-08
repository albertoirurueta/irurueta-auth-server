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

// tag::implicit-demo-page[]
(function () {
  'use strict';

  var STATE_KEY = 'legacy-implicit-state';
  var status = document.getElementById('status');
  var claims = document.getElementById('claims');
  var button = document.getElementById('sign-in');

  function randomState() {
    var bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.prototype.map.call(bytes, function (b) {
      return ('0' + b.toString(16)).slice(-2);
    }).join('');
  }

  function decodeClaims(token) {
    var parts = token.split('.');
    if (parts.length !== 3) {
      return { note: 'The access token is opaque (a reference token), there are no claims to show.' };
    }
    var base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(decodeURIComponent(Array.prototype.map.call(atob(base64), function (c) {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join('')));
  }

  function signIn() {
    var state = randomState();
    sessionStorage.setItem(STATE_KEY, state);
    var url = new URL('/oauth2/authorize', window.location.origin);
    url.searchParams.set('response_type', 'token');
    url.searchParams.set('client_id', button.dataset.clientId);
    url.searchParams.set('redirect_uri', window.location.origin + window.location.pathname);
    url.searchParams.set('scope', button.dataset.scope);
    url.searchParams.set('state', state);
    window.location.assign(url.toString());
  }

  function readFragment() {
    var fragment = window.location.hash.replace(/^#/, '');
    if (!fragment) {
      return;
    }
    var params = new URLSearchParams(fragment);
    var expected = sessionStorage.getItem(STATE_KEY);
    sessionStorage.removeItem(STATE_KEY);
    // the fragment must not stay in the address bar or in the history
    history.replaceState(null, document.title, window.location.pathname + window.location.search);
    if (!expected || params.get('state') !== expected) {
      status.textContent = 'Refused: the state of the response does not match the request (possible forgery).';
      return;
    }
    if (params.get('error')) {
      status.textContent = 'The server refused the request: ' + params.get('error');
      return;
    }
    status.textContent = 'Token received, valid for ' + params.get('expires_in') + ' seconds, scope: '
      + params.get('scope') + '.';
    claims.textContent = JSON.stringify(decodeClaims(params.get('access_token')), null, 2);
    claims.hidden = false;
  }

  button.addEventListener('click', signIn);
  readFragment();
}());
// end::implicit-demo-page[]
