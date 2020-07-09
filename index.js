var recipientPublicKey, myPrivateKey, myPublicKey, payloadArrayBuffer, inputFilename;

// Utility functions for converting between base64,
// binary strings and array buffers (byte arrays)
// from https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String

function ab2str(buf) {
  const uint8Array = new Uint8Array(buf);
  const temp = uint8Array.reduce((acc, i) => acc += String.fromCharCode.apply(null, [i]), "");
  let outputs = [];
  const length = uint8Array.byteLength;
  const CHUNK_SIZE = 50000;
  for (let i=0; i<length; i+= CHUNK_SIZE) {
    outputs.push(String.fromCharCode.apply(null, uint8Array.slice(i, i+CHUNK_SIZE)));
  }
  return outputs.join("");
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

  return pemExported;
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

  return pemExported;
}

async function pemToPublicKey(pem) {
  const pemHeader = "-----BEGIN PUBLIC KEY-----";
  const pemFooter = "-----END PUBLIC KEY-----";
  const pemSingleLine = pem.replace(/\n/g, "");
  const pemContents = pemSingleLine
    .substring(pemHeader.length, pemSingleLine.length - pemFooter.length);
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

async function pemToPrivateKey(pem) {
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const pemSingleLine = pem.replace(/\n/g, "");
  const pemContents = pemSingleLine
    .substring(pemHeader.length, pemSingleLine.length - pemFooter.length);
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

function aesKeyToArrayBuffer(key) {
  return window.crypto.subtle.exportKey(
    "raw",
    key
  );
}

function arrayBufferToAesKey(raw) {
  return window.crypto.subtle.importKey(
    "raw",
    raw,
    "AES-GCM",
    true,
    ["encrypt", "decrypt"]
  );
}

// helper functions for update the download link and global variable
function usePrivateKey(pem) {
  createLinkToDownloadPrivateKey(pem);
  pemToPrivateKey(pem).then((privateKey) => {
    myPrivateKey = privateKey;
  });
}

function createLinkToDownloadPrivateKey(pem) {
  document.querySelector(".download-private-key-button").href =
    "data:text/plain;charset=utf-8," + encodeURIComponent(pem);
}

function savePrivateKeyToLocalStorage(pem) {
  window.localStorage.setItem("privateKey", pem);
}

function loadKeysFromLocalStorageOrGenerate() {
  if (window.localStorage.getItem("privateKey") !== null) {
    loadPrivateKeyFromLocalStorage();
    loadPublicKeyFromLocalStorage();
  } else {
    generateKeyPair();
  }
}

function loadPrivateKeyFromLocalStorage() {
  const pem = window.localStorage.getItem("privateKey");
  usePrivateKey(pem);
}

function usePublicKey(pem) {
  createLinkToDownloadPublicKey(pem);
  pemToPublicKey(pem).then((publicKey) => {
    myPublicKey = publicKey;
  });
}

function createLinkToDownloadPublicKey(pem) {
  document.querySelector(".download-public-key-button").href =
    "data:text/plain;charset=utf-8," + encodeURIComponent(pem);
}

function savePublicKeyToLocalStorage(pem) {
  window.localStorage.setItem("publicKey", pem);
}

function loadPublicKeyFromLocalStorage() {
  const pem = window.localStorage.getItem("publicKey");
  usePublicKey(pem);
}

function loadPublicKeyFromFile() {
  const reader = new FileReader();
  reader.onload = async (event) => {
    recipientPublicKey = await pemToPublicKey(reader.result);
    document.querySelector(".lbl-public-key-file").textContent = this.files[0].name;
  }
  reader.readAsText(this.files[0]);
}

function loadPayloadFromFile() {
  const reader = new FileReader();
  reader.onload = async (event) => {
    payloadArrayBuffer = reader.result;
    document.querySelector(".lbl-payload").textContent = this.files[0].name;
    inputFilename = this.files[0].name;
  }
  reader.readAsArrayBuffer(this.files[0]);
}

function updateDownloadLink(action, filename, base64Encoded) {
  const downloadButton = document.querySelector("#download-payload-link");
  if (action === "lock") {
    downloadButton.download = `${filename}.locked`;
  } else {
    filename = filename.slice(0, -7);
    downloadButton.download = `${filename}`;
  }
  downloadButton.href =
    `data:application/octet-stream;base64,${base64Encoded}`
  downloadButton.click();
}

// encrypt the uploaded file, and create data URL to download encrypted file
async function encryptMessage() {
  const aesKey = await generateAESKey();
  const aesKeyArrayBuffer = await aesKeyToArrayBuffer(aesKey);
  const aesKeyEncrypted = await window.crypto.subtle.encrypt(
    {
      name: "RSA-OAEP"
    },
    recipientPublicKey,
    aesKeyArrayBuffer
  );
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const aesCiphertext = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    aesKey,
    payloadArrayBuffer
  );
  const aesKey_iv_ciphertext = new ArrayBuffer(
    aesKeyEncrypted.byteLength +
    iv.byteLength +
    aesCiphertext.byteLength);
  const outputView = new Uint8Array(aesKey_iv_ciphertext);
  outputView.set(new Uint8Array(aesKeyEncrypted), 0);
  outputView.set(iv, aesKeyEncrypted.byteLength);
  outputView.set(new Uint8Array(aesCiphertext), aesKeyEncrypted.byteLength + iv.byteLength);
  const base64Encoded = arrayBufferToBase64(aesKey_iv_ciphertext);

  updateDownloadLink("lock", inputFilename, base64Encoded);
}

// Decrypt the uploaded file, and create data URL to download decrypted file
async function decryptMessage() {
  const aesKey_iv_ciphertext = payloadArrayBuffer;
  const aesKeyEncrypted = aesKey_iv_ciphertext.slice(0, 256);
  const iv = aesKey_iv_ciphertext.slice(256, 268);
  const ciphertext = aesKey_iv_ciphertext.slice(268);
  const aesKeyArrayBuffer = await window.crypto.subtle.decrypt(
    {
      name: "RSA-OAEP"
    },
    myPrivateKey,
    aesKeyEncrypted
  );
  const aesKey = await arrayBufferToAesKey(aesKeyArrayBuffer);
  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    aesKey,
    ciphertext
  );

  updateDownloadLink("unlock", inputFilename, arrayBufferToBase64(decrypted));
}

// Generate an encryption key pair, and save to localStorage
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
  ).then(async (keyPair) => {
    const privateKeyPem = await exportPrivateKey(keyPair.privateKey);
    savePrivateKeyToLocalStorage(privateKeyPem);
    usePrivateKey(privateKeyPem);
    const publicKeyPem = await exportPublicKey(keyPair.publicKey);
    savePublicKeyToLocalStorage(publicKeyPem);
    usePublicKey(publicKeyPem);
  });
}

function generateAESKey() {
  return window.crypto.subtle.generateKey(
    {
        name: "AES-GCM",
        length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );
}


window.addEventListener('DOMContentLoaded', (event) => {
  console.log("Retrieving keys from localStorage");
  loadKeysFromLocalStorageOrGenerate();

  const generateKeyButton = document.querySelector(".generate-key-button");
  generateKeyButton.addEventListener("click", () => {
    if (window.confirm("This will replace your existing keys with new ones. Are you sure?")) {
      generateKeyPair();
    }
  });

  const encryptButton = document.querySelector(".encrypt-button");
  encryptButton.addEventListener("click", () => {
    encryptMessage();
  });

  const decryptButton = document.querySelector(".decrypt-button");
  decryptButton.addEventListener("click", () => {
    decryptMessage();
  });

  const publicKeyFileButton = document.querySelector("#public-key-file");
  publicKeyFileButton.addEventListener("change", loadPublicKeyFromFile);

  const payloadFileButton = document.querySelector("#payload-file");
  payloadFileButton.addEventListener("change", loadPayloadFromFile);
});
