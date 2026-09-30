// Signing in with a passkey: only the browser can be asked for one, which is
// what binds it to this site. Served as a file rather than inline, because the
// sign-in pages run under a Content-Security-Policy that allows scripts from
// this server only - and that policy is worth more than the convenience.
(function () {
	var button = document.getElementById("passkey-button");
	var field = document.getElementById("passkey");
	var form = document.getElementById("passkey-form");
	var error = document.getElementById("passkey-error");

	if (!button || !field || !form) {
		return;
	}

	function fromBase64url(value) {
		var padded = value.replace(/-/g, "+").replace(/_/g, "/");
		var raw = window.atob(padded);
		var bytes = new Uint8Array(raw.length);
		for (var i = 0; i < raw.length; i++) {
			bytes[i] = raw.charCodeAt(i);
		}
		return bytes.buffer;
	}

	function toBase64url(buffer) {
		var bytes = new Uint8Array(buffer);
		var raw = "";
		for (var i = 0; i < bytes.length; i++) {
			raw += String.fromCharCode(bytes[i]);
		}
		return window.btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
	}

	function show(message) {
		error.textContent = message;
		error.hidden = false;
		button.disabled = false;
	}

	button.addEventListener("click", function () {
		if (!window.PublicKeyCredential) {
			show("This browser cannot use passkeys.");
			return;
		}

		button.disabled = true;
		error.hidden = true;

		fetch(button.dataset.options, { credentials: "same-origin" })
			.then(function (res) {
				if (!res.ok) {
					throw new Error("The sign-in has expired. Start again.");
				}
				return res.json();
			})
			.then(function (options) {
				var request = options.publicKey;
				request.challenge = fromBase64url(request.challenge);
				(request.allowCredentials || []).forEach(function (credential) {
					credential.id = fromBase64url(credential.id);
				});
				return navigator.credentials.get({ publicKey: request });
			})
			.then(function (credential) {
				if (!credential) {
					throw new Error("No passkey was used.");
				}
				field.value = JSON.stringify({
					id: credential.id,
					rawId: toBase64url(credential.rawId),
					type: credential.type,
					response: {
						clientDataJSON: toBase64url(credential.response.clientDataJSON),
						authenticatorData: toBase64url(credential.response.authenticatorData),
						signature: toBase64url(credential.response.signature),
						userHandle: credential.response.userHandle
							? toBase64url(credential.response.userHandle)
							: null
					}
				});
				form.submit();
			})
			.catch(function (err) {
				show(err && err.message ? err.message : "The passkey was not used.");
			});
	});
})();
