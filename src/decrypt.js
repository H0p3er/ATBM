import { convertToNumberArray, textToBytes } from "./AES/const.js";
import { AESDecrypt } from "./AES/decrypt.js";
export function decryptData(ciperMess, key) {
    if (ciperMess) {
        var inputMess = ciperMess.split(',');
        return AESDecrypt(convertToNumberArray(inputMess), key);
    } else {
        alert('Please ensure there is encrypted text and a secret key.');
    }
}