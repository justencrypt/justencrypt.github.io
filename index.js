// Utility functions for converting between base64,
// binary strings and array buffers (byte arrays)
function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}

function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

function base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64);
    return str2ab(binaryString);
}

function arrayBufferToBase64(buffer) {
    const binaryString = ab2str(buffer)
    return window.btoa(binaryString);
}

// Utility functions for converting the keys between PEM and ArrayBuffer formats.
async function exportPrivateKey(key) {
  const exported = await window.crypto.subtle.exportKey(
    "pkcs8",
    key 
  );
  const exportedAsBase64 = arrayBufferToBase64(exported); 
  let pemExported = "-----BEGIN PRIVATE KEY-----\n";
  for (let i = 0; i < exportedAsBase64.length; i += 76) {
    pemExported += exportedAsBase64.substring(i, i + 76) + "\n";
  }
  pemExported += "-----END PRIVATE KEY-----\n";

  const exportKeyOutput = document.querySelector("#generated-private-key");
  exportKeyOutput.textContent = pemExported;
}

async function exportPublicKey(key) {
  const exported = await window.crypto.subtle.exportKey(
    "spki",
    key 
  );
  const exportedAsBase64 = arrayBufferToBase64(exported); 
  let pemExported = "-----BEGIN PUBLIC KEY-----\n"
  for (let i = 0; i < exportedAsBase64.length; i += 76) {
    pemExported += exportedAsBase64.substring(i, i + 76) + "\n";
  }
  pemExported += "-----END PUBLIC KEY-----\n";
  const exportKeyOutput = document.querySelector("#generated-public-key");
  exportKeyOutput.textContent = pemExported;
}

async function importPublicKey() {
  const pem = document.querySelector("#generated-public-key").value.replace(/\n/g, "");
  const pemHeader = "-----BEGIN PUBLIC KEY-----";
  const pemFooter = "-----END PUBLIC KEY-----";
  const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length);
  const binaryDer = base64ToArrayBuffer(pemContents);

  return window.crypto.subtle.importKey(
    "spki",
    binaryDer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256"
    },
    true,
    ["encrypt"]
  );
}

function importPrivateKey() {
  const pem = document.querySelector("#generated-private-key").value.replace(/\n/g, "");
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length);
  const binaryDer = base64ToArrayBuffer(pemContents);

  return window.crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["decrypt"]
  );
}

// Get the encoded message, encrypt it and display a representation
// of the ciphertext in the "Ciphertext" element.
async function encryptMessage() {
  const publicKey = await importPublicKey();
  const plaintext = document.querySelector("#plaintext").value;
  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: "RSA-OAEP"
    },
    publicKey,
    str2ab(plaintext)
  );
  const ciphertextValue = document.querySelector("#ciphertext");
  ciphertextValue.value = arrayBufferToBase64(ciphertext);
}

// Fetch the ciphertext and decrypt it.
// Write the decrypted message into the "Decrypted" box.
async function decryptMessage() {
  const privateKey = await importPrivateKey();
  const ciphertextValue = document.querySelector("#ciphertext");
  let decrypted = await window.crypto.subtle.decrypt(
    {
      name: "RSA-OAEP"
    },
    privateKey,
    base64ToArrayBuffer(ciphertextValue.value)
  );

  let dec = new TextDecoder();
  const decryptedValue = document.querySelector("#plaintext");
  decryptedValue.value = dec.decode(decrypted);
}

// Generate an encryption key pair, then display to user
function generateKeyPair() {
  window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  ).then((keyPair) => {
    exportPrivateKey(keyPair.privateKey);
    exportPublicKey(keyPair.publicKey);
  });
}

const generateKeyButton = document.querySelector(".generate-key-button");
generateKeyButton.addEventListener("click", () => {
  generateKeyPair();
});

const encryptButton = document.querySelector(".encrypt-button");
encryptButton.addEventListener("click", () => {
  encryptMessage();
});

const decryptButton = document.querySelector(".decrypt-button");
decryptButton.addEventListener("click", () => {
  decryptMessage();
});
