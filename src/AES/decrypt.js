import { inv_s, mul9, mul11, mul13, mul14, KeyExpansion, bytesToText, unpadMessage } from "./const.js";

function AddRoundKey(state, roundKey) {
	for (let i = 0; i < 16; i++) {
		state[i] ^= roundKey[i];
	}
}

/* InverseMixColumns uses mul9, mul11, mul13, mul14 look-up tables
 * Unmixes the columns by reversing the effect of MixColumns in encryption
 */
function InverseMixColumns(state) {
	let tmp = [...state];

	for(var i = 0; i < 4; i++) {
		state[0 * 4 + i] = mul14[state[0 + i]] ^ mul11[state[1 * 4 + i]] ^ mul13[state[2 * 4 + i]] ^ mul9[state[3 * 4 + i]];
		state[1 * 4 + i] = mul9[state[0 * 4 + i]] ^ mul14[state[1 * 4 + i]] ^ mul11[state[2 * 4 + i]] ^ mul13[state[3 * 4 + i]];	
		state[2 * 4 + i] = mul13[state[0 * 4 + i]] ^ mul9[state[1 * 4 + i]] ^ mul14[state[2 * 4 + i]] ^ mul11[state[3 * 4 + i]];
		state[3 * 4 + i] = mul11[state[0 * 4 + i]] ^ mul13[state[1 * 4 + i]] ^ mul9[state[2 * 4 + i]] ^ mul14[state[3 * 4 + i]];
	}
}

// Shifts rows right (rather than left) for decryption
function InvShiftRows(state) {
	let tmp = [...state];

	for(var i = 1; i < 4; i++) {
		for(var j = 0; j < 4; j++) {
			state[i * 4 + j] = tmp[i * 4 + ((Math.abs(j - i)) % 4)];
		}
	}
	

	/* Column 1 */
	// tmp[0] = state[0];
	// tmp[1] = state[13];
	// tmp[2] = state[10];
	// tmp[3] = state[7];

	// /* Column 2 */
	// tmp[4] = state[4];
	// tmp[5] = state[1];
	// tmp[6] = state[14];
	// tmp[7] = state[11];

	// /* Column 3 */
	// tmp[8] = state[8];
	// tmp[9] = state[5];
	// tmp[10] = state[2];
	// tmp[11] = state[15];

	// /* Column 4 */
	// tmp[12] = state[12];
	// tmp[13] = state[9];
	// tmp[14] = state[6];
	// tmp[15] = state[3];

	// for (let i = 0; i < 16; i++) {
	// 	state[i] = tmp[i];
	// }
}

/* Perform substitution to each of the 16 bytes
 * Uses inverse S-box as lookup table
 */
function InvSubBytes(state) {
	for (let i = 0; i < 4; i++) { // Perform substitution to each of the 16 bytes
		for(var j = 0; j < 4; j++) {
			state[i * 4 + j] = inv_s[state[i * 4 + j]];
		}
	}
}

/* Each round operates on 128 bits at a time
 * The number of rounds is defined in AESDecrypt()
 * Not surprisingly, the steps are the encryption steps but reversed
 */
function Round(state, key) {
	InvShiftRows(state);
	InvSubBytes(state);
	AddRoundKey(state, key);
	InverseMixColumns(state);
}

// Same as Round() but no InverseMixColumns
function FinalRound(state, key) {
	InvShiftRows(state);
	InvSubBytes(state);
	AddRoundKey(state, key);
}

/* The AES decryption function
 * Organizes all the decryption steps into one function
 */
function AESDecryptBlock(encryptedMessage, expandedKey, Nr = 10)
{
  	let decryptedMessage = []
	let state = []; // Stores the first 16 bytes of encrypted message
	
	for (let i = 0; i < 4; i++) {
		for (let j = 0; j<4 ; j++){
			state[i+4*j] = encryptedMessage[i*4+j];
		}
	}

	AddRoundKey(state, expandedKey.slice(Nr * 16, (Nr + 1) * 16)); // Final round

	let numberOfRounds = 9;
	
	for (let round = Nr - 1; round > 0; round--) {
		Round(state, expandedKey.slice(round * 16, (round + 1) * 16));
	}
	
	FinalRound(state, expandedKey.slice(0,16));

	// Copy decrypted state to buffer
	for (let i = 0; i < 4; i++) {
		for (let j = 0; j<4;j++){
			decryptedMessage[i*4+j] = state[i+4*j];
		}
	}
  return decryptedMessage;
}

export function AESDecrypt(encryptedMessage = [], key){
  	let expandedKey = KeyExpansion(key);
	let messageLen = encryptedMessage.length;
	let decryptedMessage = [];
	for (let i = 0; i < messageLen; i += 16) {
		var block = encryptedMessage.slice(i, i + 16);
		console.log("block: ", block);
		decryptedMessage.push(...AESDecryptBlock(block, expandedKey));
	}
  	return bytesToText(decryptedMessage);
}
