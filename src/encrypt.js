
import { AESEncrypt } from "./AES/encrypt.js";

export function encryptData(plainText, key) {
    
    if (plainText !=null) {
        return AESEncrypt(new TextEncoder().encode(plainText), key).toString();
    } else {
        alert('Please enter both text to encrypt and a secret key.');
        return "";
    }
}
