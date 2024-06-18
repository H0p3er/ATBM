import { s, mul9, mul11, mul13, mul14, KeyExpansion } from "./const.js";

function SubRoundKey(state, roundKey) {
	for (let i = 0; i < 16; i++) {
		state[i] ^= roundKey[i];
	}
}

/* InverseMixColumns uses mul9, mul11, mul13, mul14 look-up tables
 * Unmixes the columns by reversing the effect of MixColumns in encryption
 */
function InverseMixColumns(state) {
	let tmp = [];

	tmp[0] = mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]];
	tmp[1] = mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]];
	tmp[2] = mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]];
	tmp[3] = mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]];

	tmp[4] = mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]];
	tmp[5] = mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]];
	tmp[6] = mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]];
	tmp[7] = mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]];

	tmp[8] = mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]];
	tmp[9] = mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]];
	tmp[10] = mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]];
	tmp[11] = mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]];

	tmp[12] = mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]];
	tmp[13] = mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]];
	tmp[14] = mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]];
	tmp[15] = mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]];

	for (let i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

// Shifts rows right (rather than left) for decryption
function ShiftRows(state) {
	let tmp = [];

	/* Column 1 */
	tmp[0] = state[0];
	tmp[1] = state[13];
	tmp[2] = state[10];
	tmp[3] = state[7];

	/* Column 2 */
	tmp[4] = state[4];
	tmp[5] = state[1];
	tmp[6] = state[14];
	tmp[7] = state[11];

	/* Column 3 */
	tmp[8] = state[8];
	tmp[9] = state[5];
	tmp[10] = state[2];
	tmp[11] = state[15];

	/* Column 4 */
	tmp[12] = state[12];
	tmp[13] = state[9];
	tmp[14] = state[6];
	tmp[15] = state[3];

	for (let i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

/* Perform substitution to each of the 16 bytes
 * Uses inverse S-box as lookup table
 */
function SubBytes(state) {
	for (let i = 0; i < 16; i++) { // Perform substitution to each of the 16 bytes
		state[i] = inv_s[state[i]];
	}
}

/* Each round operates on 128 bits at a time
 * The number of rounds is defined in AESDecrypt()
 * Not surprisingly, the steps are the encryption steps but reversed
 */
function Round(state, key) {
	SubRoundKey(state, key);
	InverseMixColumns(state);
	ShiftRows(state);
	SubBytes(state);
}

// Same as Round() but no InverseMixColumns
function InitialRound(state, key) {
	SubRoundKey(state, key);
	ShiftRows(state);
	SubBytes(state);
}

/* The AES decryption function
 * Organizes all the decryption steps into one function
 */
function AESDecryptBlock(encryptedMessage, expandedKey)
{
    let decryptedMessage = []
	let state = []; // Stores the first 16 bytes of encrypted message

	for (let i = 0; i < 16; i++) {
		state[i] = encryptedMessage[i];
	}

	InitialRound(state, expandedKey+160);

	let numberOfRounds = 9;

	for (let i = 8; i >= 0; i--) {
		Round(state, expandedKey + (16 * (i + 1)));
	}

	SubRoundKey(state, expandedKey); // Final round

	// Copy decrypted state to buffer
	for (let i = 0; i < 16; i++) {
		decryptedMessage[i] = state[i];
	}
    return decryptedMessage;
}

export function AESDecrypt(encryptedMessage, key){
    let expandedKey;
	KeyExpansion(key, expandedKey);
	
	let messageLen = encryptedMessage.length;

	let decryptedMessage = '';

	for (let i = 0; i < messageLen; i += 16) {
		decryptedMessage+=AESDecryptBlock(encryptedMessage, expandedKey);
	}

    return decryptedMessage;
}
