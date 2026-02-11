const crypto = require("crypto");

const key = Buffer.from('ok3S9pbTo520Fosnt6pXne7Tq2SMhbx0'); // 32 bytes key for AES-256
const iv = Buffer.from('pKs20Tsky9Lso61B'); // 16 bytes IV for AES-256

function decryptMessage(encryptedText) {
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  let decrypted = decipher.update(encryptedText, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

function encryptMessage(text) {
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(text, "utf8", "base64");
  encrypted += cipher.final("base64");
  return encrypted;
}


module.exports = { decryptMessage, encryptMessage };