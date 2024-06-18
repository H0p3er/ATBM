
export function generateKey(KEY_LENGTH){
    let initKey = "";
    for (let i = 0; i<KEY_LENGTH;i++){
        initKey += Math.floor(Math.random() * 16).toString(16);
    }
    return new TextEncoder().encode(initKey);
}


