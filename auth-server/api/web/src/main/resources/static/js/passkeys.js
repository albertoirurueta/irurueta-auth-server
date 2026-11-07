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

"use strict";

/*
 * Browser side of the passkeys (WebAuthn). One external, same-origin script, so the Content-Security-Policy of the
 * pages (default-src 'self') needs no nonce and no hash. It drives three pieces of markup, each found by its data
 * attribute:
 *  - [data-passkey-login]: the passkey sign-in of the login page and of the second-factor page. A button starts the
 *    ceremony; when the container also has a [data-passkey-field] (an input with autocomplete="username webauthn")
 *    and the browser supports it, the passkeys are offered in that field too (conditional mediation).
 *  - [data-passkey-register]: the registration of the account page: a name for the passkey
 *    ([data-passkey-label]) and a button. The options returned by the server (including excludeCredentials, so the
 *    authenticator is not registered twice) are handed to the browser as they are, after decoding their binary
 *    fields from base64url.
 * The containers carry the CSRF header name and token and the messages they show, so nothing is inlined here.
 * The endpoints are the ones of Spring Security's WebAuthn filters.
 */
(function () {
  var OPTIONS_PATH = "/webauthn/authenticate/options";
  var LOGIN_PATH = "/login/webauthn";
  var REGISTER_OPTIONS_PATH = "/webauthn/register/options";
  var REGISTER_PATH = "/webauthn/register";

  var base64url = {
    encode: function (buffer) {
      var binary = "";
      new Uint8Array(buffer).forEach(function (byte) {
        binary += String.fromCharCode(byte);
      });
      return window.btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    },
    decode: function (text) {
      var binary = window.atob(text.replace(/-/g, "+").replace(/_/g, "/"));
      var bytes = new Uint8Array(binary.length);
      for (var i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes.buffer;
    }
  };

  /** The server refused or could not process a request of a ceremony (as opposed to the user cancelling it). */
  function ServerError(message) {
    this.name = "ServerError";
    this.message = message;
  }

  var current = null;

  /** Cancels the ceremony in progress, if any, and gives the signal of the next one. */
  function newSignal() {
    if (current) {
      current.abort();
    }
    current = new AbortController();
    return current.signal;
  }

  function headersOf(container) {
    var headers = { "Content-Type": "application/json" };
    if (container.dataset.csrfHeader && container.dataset.csrfToken) {
      headers[container.dataset.csrfHeader] = container.dataset.csrfToken;
    }
    return headers;
  }

  function post(container, path, body) {
    return fetch(path, {
      method: "POST",
      headers: headersOf(container),
      credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body)
    });
  }

  function show(element, message) {
    if (!element) {
      return;
    }
    element.textContent = message;
    element.hidden = false;
  }

  function hide(element) {
    if (element) {
      element.hidden = true;
    }
  }

  // tag::passkeys-authenticate[]
  /**
   * Runs an authentication ceremony and returns the URL the server wants the browser to go to next (the saved
   * authorization request, or the root).
   */
  async function authenticate(container, conditional) {
    var optionsResponse = await post(container, OPTIONS_PATH);
    if (!optionsResponse.ok) {
      throw new ServerError("options " + optionsResponse.status);
    }
    var options = await optionsResponse.json();
    options.challenge = base64url.decode(options.challenge);
    options.allowCredentials = (options.allowCredentials || []).map(function (credential) {
      return Object.assign({}, credential, { id: base64url.decode(credential.id) });
    });
    var request = { publicKey: options, signal: newSignal() };
    if (conditional) {
      request.mediation = "conditional";
    }
    var credential = await navigator.credentials.get(request);
    var response = credential.response;
    var loginResponse = await post(container, LOGIN_PATH, {
      id: credential.id,
      rawId: base64url.encode(credential.rawId),
      response: {
        authenticatorData: base64url.encode(response.authenticatorData),
        clientDataJSON: base64url.encode(response.clientDataJSON),
        signature: base64url.encode(response.signature),
        userHandle: response.userHandle ? base64url.encode(response.userHandle) : undefined
      },
      type: credential.type,
      clientExtensionResults: credential.getClientExtensionResults(),
      authenticatorAttachment: credential.authenticatorAttachment
    });
    if (!loginResponse.ok) {
      throw new ServerError("login " + loginResponse.status);
    }
    var result = await loginResponse.json();
    if (!result || !result.authenticated || !result.redirectUrl) {
      throw new ServerError("unexpected answer");
    }
    return result.redirectUrl;
  }
  // end::passkeys-authenticate[]

  async function signIn(container, conditional) {
    var error = container.querySelector("[data-passkey-error]");
    hide(error);
    try {
      window.location.href = await authenticate(container, conditional);
    } catch (failure) {
      if (failure instanceof ServerError) {
        window.location.href = container.dataset.errorUrl;
      } else if (!conditional && failure.name !== "AbortError") {
        show(error, container.dataset.failureMessage);
      }
    }
  }

  function setUpLogin(container) {
    var button = container.querySelector("[data-passkey-button]");
    if (button) {
      button.addEventListener("click", function () {
        signIn(container, false);
      });
    }
    var field = container.querySelector("[data-passkey-field]");
    if (field && window.PublicKeyCredential && window.PublicKeyCredential.isConditionalMediationAvailable) {
      window.PublicKeyCredential.isConditionalMediationAvailable().then(function (available) {
        if (available) {
          signIn(container, true);
        }
      });
    }
  }

  // tag::passkeys-register[]
  /** Runs a registration ceremony for a passkey with the given name. */
  async function register(container, label) {
    var optionsResponse = await post(container, REGISTER_OPTIONS_PATH);
    if (optionsResponse.redirected) {
      // the session still has to complete its second factor: let the server send it there
      window.location.href = optionsResponse.url;
      return false;
    }
    if (!optionsResponse.ok) {
      throw new ServerError("options " + optionsResponse.status);
    }
    var options = await optionsResponse.json();
    options.challenge = base64url.decode(options.challenge);
    options.user = Object.assign({}, options.user, { id: base64url.decode(options.user.id) });
    options.excludeCredentials = (options.excludeCredentials || []).map(function (credential) {
      return Object.assign({}, credential, { id: base64url.decode(credential.id) });
    });
    var created = await navigator.credentials.create({ publicKey: options, signal: newSignal() });
    var response = created.response;
    var registerResponse = await post(container, REGISTER_PATH, {
      publicKey: {
        credential: {
          id: created.id,
          rawId: base64url.encode(created.rawId),
          response: {
            attestationObject: base64url.encode(response.attestationObject),
            clientDataJSON: base64url.encode(response.clientDataJSON),
            transports: response.getTransports ? response.getTransports() : []
          },
          type: created.type,
          clientExtensionResults: created.getClientExtensionResults(),
          authenticatorAttachment: created.authenticatorAttachment
        },
        label: label
      }
    });
    if (!registerResponse.ok) {
      throw new ServerError("register " + registerResponse.status);
    }
    var result = await registerResponse.json();
    if (!result || !result.success) {
      throw new ServerError("unexpected answer");
    }
    return true;
  }
  // end::passkeys-register[]

  function setUpRegistration(container) {
    var button = container.querySelector("[data-passkey-register-button]");
    var input = container.querySelector("[data-passkey-label]");
    var error = container.querySelector("[data-passkey-error]");
    var status = container.querySelector("[data-passkey-status]");
    if (!button || !input) {
      return;
    }
    button.addEventListener("click", async function () {
      hide(error);
      hide(status);
      var label = input.value.trim();
      if (!label) {
        show(error, container.dataset.labelMessage);
        return;
      }
      try {
        if (await register(container, label)) {
          show(status, container.dataset.successMessage);
          window.location.reload();
        }
      } catch (failure) {
        show(error, container.dataset.failureMessage);
      }
    });
  }

  function setUp() {
    document.querySelectorAll("[data-passkey-login]").forEach(setUpLogin);
    document.querySelectorAll("[data-passkey-register]").forEach(setUpRegistration);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setUp);
  } else {
    setUp();
  }
})();
