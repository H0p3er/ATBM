import { encryptData } from "./encrypt.js";
import { decryptData } from "./decrypt.js";
import { generateKey } from "./key.js"; 
import { download } from "./file.js";

let encryptedText = ""
let plainText = "";
let key = generateKey(16);;

document.getElementById("encryptBtn").addEventListener("click",()=>{
    key = generateKey(16);
    plainText = document.getElementById('plainText').value;
    encryptedText = encryptData(plainText,key);
    document.getElementById('encryptedText').value = encryptedText;
})

document.getElementById("decryptBtn").addEventListener("click",()=>{
    encryptedText = document.getElementById('cipherText').value;
    document.getElementById('decryptedText').value = decryptData(encryptedText,key);
})

//Khởi tạo file
document.getElementById("saveDecryptBtn").addEventListener("click",()=>{
    let encoder = new TextEncoder();
    let data = decryptData(encryptedText,key);
    download(data, 'decrypt.txt', 'text/plain');
    download(key, 'key.txt', 'text/plain');
})

document.getElementById("saveEncryptBtn").addEventListener("click",()=>{
    let encoder = new TextEncoder();
    let data = encryptData(plainText,key)
    download(data, 'encrypt.txt', 'text/plain');
    download(key, 'key.txt', 'text/plain');
})

document.getElementById("changeValue").addEventListener("click",()=>{
    document.getElementById('cipherText').value = document.getElementById('encryptedText').value;
})

document.getElementById('importEncryptFile').addEventListener( 'change', importEncryptFile, false );

document.getElementById('importPlainTextFile').addEventListener( 'change',  importDecryptFile, false );



export function importEncryptFile( evt ) {
    const reader = new FileReader()
    reader.onload = (event)=>{
        document.getElementById('cipherText').value = event.target.result;
    };

    reader.readAsText(evt.target.files[0]) 
}

export function importDecryptFile( evt ) {
    const reader = new FileReader()
    reader.onload = (event)=>{
        document.getElementById('plainText').value =  event.target.result;
    };
    reader.readAsText(evt.target.files[0]) 
}
