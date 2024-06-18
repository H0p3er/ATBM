const { Rcon } = require('../Const/Rcon');
const { xorWords,subWord,rotWord } = require('../utilities');


function addRoundKey(state, roundKey) {
    for (let row = 0; row < state.length; row++) {
        for (let col = 0; col < state[row].length; col++) {
            state[row][col] ^= roundKey[row][col];
        }
    }
    return state;
}

function keyExpansion(key) {
    const Nb = 4;  // Number of columns (32-bit words) comprising the State. For AES, Nb = 4.
    const Nk = key.length / 4;  // The number of 32-bit words comprising the Cipher Key.
    const Nr = Nk + 6;  // The number of rounds in AES Cipher.
    const w = new Array(Nb * (Nr + 1));  // Key schedule array
    let temp = new Array(4);

    for (let i = 0; i < Nk; i++) {
        w[i] = key.slice(4 * i, 4 * (i + 1));
    }

    for (let i = Nk; i < Nb * (Nr + 1); i++) {
        temp = w[i - 1].slice();
        if (i % Nk === 0) {
            temp = xorWords(subWord(rotWord(temp)), [(Rcon[i / Nk] >> 24) & 0xff, (Rcon[i / Nk] >> 16) & 0xff, (Rcon[i / Nk] >> 8) & 0xff, Rcon[i / Nk] & 0xff]);
        } else if (Nk > 6 && i % Nk === 4) {
            temp = subWord(temp);
        }
        w[i] = xorWords(w[i - Nk], temp);
    }

    return w;
}

module.exports = {
    keyExpansion
};


module.exports = {
    addRoundKey
};