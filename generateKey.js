const { generateKeyPairSync } = require("crypto");
const fs = require("fs");

const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: "spki",
        format: "pem",
    },
    privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
    },
});

if (!fs.existsSync("keys")) {
    fs.mkdirSync("keys");
}

fs.writeFileSync("keys/private.key", privateKey);
fs.writeFileSync("keys/public.key", publicKey);

console.log("Đã tạo key thành công!");