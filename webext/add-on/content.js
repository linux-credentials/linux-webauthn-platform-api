let requestCounter = 0;
const pendingRequests = {}
var webauthnPort = browser.runtime.connect({ name: "credential_manager_shim" });
console.log("loading content")

webauthnPort.onMessage.addListener(({ requestId, data, error }) => {
    console.log('received message from background script:')
    console.log(data);
    endRequest(requestId, data, error);
});

console.log("overriding navigator.credentials in content script");
exportFunction(createCredential, navigator.credentials, { defineAs: "create"})
exportFunction(getCredential, navigator.credentials, { defineAs: "get"})


if (window.PublicKeyCredential) {
  console.log("overriding PublicKeyCredential.getClientCapabilities() in content script");
  exportFunction(getClientCapabilities, PublicKeyCredential, { defineAs: "getClientCapabilities"})
}

function startRequest() {
    const requestId = requestCounter++;
    const {promise, resolve, reject } = window.Promise.withResolvers();
    pendingRequests[requestId] = { resolve, reject }
    return { requestId, promise }
}

function endRequest(requestId, data, error) {
    const request = pendingRequests[requestId]
    if (error) {
        request.reject(error)
    } else {
        request.resolve(data)
    }
}

async function cloneCredentialResponse(credential) {
    try {
        const options = { alphabet: "base64url" }
        const obj = {}
        obj.id = credential.id;
        obj.rawId = cloneInto(Uint8Array.fromBase64(credential.rawId, options), obj)
        obj.authenticatorAttachment = credential.authenticatorAttachment;
        const response = {}
        // credential registration response
        if (credential.response.attestationObject) {
            const clientDataJSON = credential.response.clientDataJSON
            response.clientDataJSON = Uint8Array.fromBase64(clientDataJSON, options)
            const attestationObject = credential.response.attestationObject
            response.attestationObject = Uint8Array.fromBase64(attestationObject, options)
            response.transports = [...credential.response.transports]
            const authenticatorData = Uint8Array.fromBase64(credential.response.authenticatorData, options)
            response.authenticatorData = cloneInto(authenticatorData, response)
            response.getAuthenticatorData = function() {
                return this.authenticatorData
            }
            response.getPublicKeyAlgorithm = function() {
                const publicKeyAlgorithm = credential.response.publicKeyAlgorithm
                return publicKeyAlgorithm
            }
            const publicKey = Uint8Array.fromBase64(credential.response.publicKey, options)
            response.publicKey = cloneInto(publicKey, response)
            response.getPublicKey = function() {
                return this.publicKey
            }
            response.getTransports = function() {
                return this.transports
            }

        }
        // credential attestation response
        else if (credential.response.signature) {
            const clientDataJSON = credential.response.clientDataJSON
            response.clientDataJSON = Uint8Array.fromBase64(clientDataJSON, options)
            const authenticatorData = Uint8Array.fromBase64(credential.response.authenticatorData, options)
            response.authenticatorData = cloneInto(authenticatorData, response)
            const signature = Uint8Array.fromBase64(credential.response.signature, options)
            response.signature = cloneInto(signature, response)
            if (credential.response.userHandle) {
                const userHandle = Uint8Array.fromBase64(credential.response.userHandle, options)
                response.userHandle = cloneInto(userHandle, response)
            }
            else {
                response.userHandle = null
            }
        }
        else {
            throw cloneInto(new Error("Unknown credential response type received"), window)
        }

        // Unlike CreatePublicKey, for GetPublicKey, we have a lot of Byte arrays,
        // so we need a lot of deconstructions. So no: obj.clientExtensionResults = cloneInto(credential.clientExtensionResults, obj);
        const extensions = {}
        if (credential.clientExtensionResults) {
            if (credential.clientExtensionResults.hmacGetSecret) {
                extensions.hmacGetSecret = {}
                extensions.hmacGetSecret.output1 = Uint8Array.fromBase64(credential.clientExtensionResults.hmacGetSecret.output1, options);
                if (credential.clientExtensionResults.hmacGetSecret.output2) {
                    extensions.hmacGetSecret.output2 = Uint8Array.fromBase64(credential.clientExtensionResults.hmacGetSecret.output2, options);
                }
            }

            if (credential.clientExtensionResults.prf) {
                extensions.prf = {}
                if (credential.clientExtensionResults.prf.results) {
                    extensions.prf.results = {}
                    extensions.prf.results.first = Uint8Array.fromBase64(credential.clientExtensionResults.prf.results.first, options);
                    if (credential.clientExtensionResults.prf.results.second) {
                        extensions.prf.results.second = Uint8Array.fromBase64(credential.clientExtensionResults.prf.results.second, options);
                    }
                }
                if (credential.clientExtensionResults.prf.enabled) {
                    extensions.prf.enabled = cloneInto(credential.clientExtensionResults.prf.enabled, extensions.prf)
                }
            }

            if (credential.clientExtensionResults.largeBlob) {
                extensions.largeBlob = {}
                if (credential.clientExtensionResults.largeBlob.blob) {
                    extensions.largeBlob.blob = Uint8Array.fromBase64(credential.clientExtensionResults.largeBlob.blob, options);
                }
            }

            if (credential.clientExtensionResults.credProps) {
                extensions.credProps = cloneInto(credential.clientExtensionResults.credProps, extensions)
            }
        }
        obj.response = cloneInto(response, obj, { cloneFunctions: true })
        obj.clientExtensionResults = extensions;
        obj.getClientExtensionResults = function() {
            return this.clientExtensionResults;
        }
        obj.type = "public-key"

        obj.toJSON = function() {
            json = new window.Object();
            json.id = this.id
            json.rawId = this.id

            json.response = new window.Object()
            // credential registration response
            if (credential.response.attestationObject) {
                json.response.clientDataJSON = credential.response.clientDataJSON
                json.response.authenticatorData = credential.response.authenticatorData
                json.response.transports = this.transports
                json.response.publicKey = credential.response.publicKey
                json.response.publicKeyAlgorithm = credential.response.publicKeyAlgorithm
                json.response.attestationObject = credential.response.attestationObject
            }
            // credential attestation response
            else if (credential.response.signature) {
                json.response.clientDataJSON = credential.response.clientDataJSON
                json.response.authenticatorData = credential.response.authenticatorData
                json.response.signature = credential.response.signature
                json.response.userHandle = credential.response.userHandle
            }
            else {
                throw cloneInto(new Error("Unknown credential type received"), window)
            }

            json.authenticatorAttachment = this.authenticatorAttachment;
            json.clientExtensionResults = this.clientExtensionResults;
            json.type = this.type
            return json
        }
        return cloneInto(obj, window, { cloneFunctions: true })
    }
    catch (error) {
        console.error(error)
        throw cloneInto(error, window)
    }
}

function createCredential(request) {
    console.log("forwarding create call from content script to background script")
    console.log(webauthnPort)
    console.log(request)

    // the signal object can't be sent to background script, so omit it
    const { signal, ...options} = request

    const { requestId, promise } = startRequest();
    webauthnPort.postMessage({ requestId, cmd: 'create', options, })
    return promise.then(cloneCredentialResponse)
}

function getCredential(request) {
    console.log("forwarding get call from content script to background script")
    // the signal object can't be sent to background script, so omit it
    const { /** @type {AbortSignal} */signal, ...options} = request

    const { requestId, promise } = startRequest();
    webauthnPort.postMessage({ requestId, cmd: 'get', options, })
    return promise.then(cloneCredentialResponse)
};

function getClientCapabilities() {
    console.log("forwarding getClientCapabilities call from content script to background script")
    const { requestId, promise } = startRequest();
    webauthnPort.postMessage({ requestId, cmd: 'getClientCapabilities', })
    return promise.then((capabilities) => cloneInto(capabilities, window))
};
