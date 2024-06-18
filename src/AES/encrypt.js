import { s, mul2, mul3, KeyExpansion } from "./const.js";

function AddRoundKey(state, roundKey) {
	for (let i = 0; i < 16; i++) {
		state[i] ^= roundKey[i];
	}
}

/* Perform substitution to each of the 16 bytes
 * Uses S-box as lookup table 
 */
function SubBytes(state) {
	for (let i = 0; i < 16; i++) {
		state[i] = s[state[i]];
	}
}

// Shift left, adds diffusion
function ShiftRows(state) {
	let tmp = new Uint8Array();

	/* Column 1 */
	tmp[0] = state[0];
	tmp[1] = state[5];
	tmp[2] = state[10];
	tmp[3] = state[15];
	
	/* Column 2 */
	tmp[4] = state[4];
	tmp[5] = state[9];
	tmp[6] = state[14];
	tmp[7] = state[3];

	/* Column 3 */
	tmp[8] = state[8];
	tmp[9] = state[13];
	tmp[10] = state[2];
	tmp[11] = state[7];
	
	/* Column 4 */
	tmp[12] = state[12];
	tmp[13] = state[1];
	tmp[14] = state[6];
	tmp[15] = state[11];

	for (let i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

 /* MixColumns uses mul2, mul3 look-up tables
  * Source of diffusion
  */
function MixColumns(state) {
	let tmp = new Uint8Array();

	tmp[0] = mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3];
	tmp[1] = state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3];
	tmp[2] = state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]];
	tmp[3] = mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]];

	tmp[4] = mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7];
	tmp[5] = state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7];
	tmp[6] = state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]];
	tmp[7] = mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]];

	tmp[8] = mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11];
	tmp[9] = state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11];
	tmp[10] = state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]];
	tmp[11] = mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]];

	tmp[12] = mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15];
	tmp[13] = state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15];
	tmp[14] = state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]];
	tmp[15] = mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]];

	for (let i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

/* Each round operates on 128 bits at a time
 * The number of rounds is defined in AESEncrypt()
 */
function Round(state, key) {
	SubBytes(state);
	ShiftRows(state);
	MixColumns(state);
	AddRoundKey(state, key);
}

 // Same as Round() except it doesn't mix columns
function FinalRound(state, key) {
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, key);
}

/* The AES encryption function
 * Organizes the confusion and diffusion steps into one function
 */
function AESEncryptBlock(message, expandedKey) {

	let state = new Uint8Array(); // Stores the first 16 bytes of original message

    console.log(message);
    console.log(expandedKey);
	for (let i = 0; i < 16; i++) {
        console.log(state[i]);
		state[i] = message[i];
	}

    console.log(state);
	let numberOfRounds = 9;

	AddRoundKey(state, expandedKey); // Initial round

	for (let i = 0; i < numberOfRounds; i++) {
		Round(state, expandedKey + (16 * (i+1)));
	}

	FinalRound(state, expandedKey + 160);

    let encryptedMessage = new Uint8Array();
	// Copy encrypted state to buffer
	for (let i = 0; i < 16; i++) {
		encryptedMessage[i] = state[i];
	}
    return encryptedMessage;
}


export function AESEncrypt(message, key){
    let expandedKey = new Uint8Array();
    let encryptedMessage = '';

    KeyExpansion(key, expandedKey);

    let originalLen = message.length;

    let paddedMessageLen = originalLen;

    if ((paddedMessageLen % 16) != 0) {
        paddedMessageLen = (paddedMessageLen / 16 + 1) * 16;
    }

    let paddedMessage = new Uint8Array();
    for (let j = 0; j < paddedMessageLen; j++) {
        if (j >= originalLen) {
            paddedMessage[j] = 0;
        }
        else {
            paddedMessage[j] = message[j];
        }
    }

    for (let i = 0; i < paddedMessageLen; i += 16) {
        let messageBlock = new Uint8Array();
        for (let j =0 ; j < i; j++){
            messageBlock[j] = paddedMessage[i+j]
        }
        encryptedMessage +=new TextDecoder().decode(AESEncryptBlock(messageBlock, expandedKey));
	}

    return encryptedMessage;
}
