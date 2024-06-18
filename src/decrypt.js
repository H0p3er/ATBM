import { AESDecrypt } from "./AES/decrypt.js";
export function decryptData(encryptedText, key) {
    if (encryptedText!=null) {
        return AESDecrypt(TextEncoder().encode(encryptedText), key).toString();
    } else {
        alert('Please ensure there is encrypted text and a secret key.');
    }
}