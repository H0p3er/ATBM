import { AESEncrypt } from "./AES/encrypt.js";
import { textToBytes } from "./AES/const.js";

export function encryptData(plainText, key) {
    
    if (plainText !=null) {
        const input = textToBytes(plainText);
        var ciperMess = AESEncrypt(input, key);
        return ciperMess;
    } else {
        alert('Please enter both text to encrypt and a secret key.');
        return "";
    }
}
