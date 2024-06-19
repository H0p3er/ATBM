import { s, mul2, mul3, KeyExpansion, padMessage } from "./const.js";

// Hàm xoay vòng một từ (4 byte)
function rotWord(word) {
	return word.slice(1).concat(word[0]);
}

// Hàm thay thế từng byte của một từ theo S-box
function subWord(word) {
	return word.map(byte => s[byte]);
}

function AddRoundKey(state, roundKey) {
	for (let i = 0; i < 16; i++) {
		state[i] ^= roundKey[i];
	}
}

/* 
	Thay thế từng byte trong state bằng giá trị tương ứng trong S-box.
 */
function SubBytes(state) {
	for (let i = 0; i < 16; i++) {
		state[i] = s[state[i]];
	}
}

// Dịch chuyển hàng của state sang trái.
function ShiftRows(state) {
	let tmp = [...state];

	// /* Column 1 */
	// tmp[0] = state[0];
	// tmp[1] = state[5];
	// tmp[2] = state[10];
	// tmp[3] = state[15];
	
	// /* Column 2 */
	// tmp[4] = state[4];
	// tmp[5] = state[9];
	// tmp[6] = state[14];
	// tmp[7] = state[3];

	// /* Column 3 */
	// tmp[8] = state[8];
	// tmp[9] = state[13];
	// tmp[10] = state[2];
	// tmp[11] = state[7];
	
	// /* Column 4 */
	// tmp[12] = state[12];
	// tmp[13] = state[1];
	// tmp[14] = state[6];
	// tmp[15] = state[11];

	for (let i = 0; i < 4; i++) {
		for( let j = 0; j < 4; j++) {
			state[i * 4 + j] = tmp[i * 4 + ((i + j) % 4)];
		}
	}
}

 /* MixColumns uses mul2, mul3 look-up tables
  * Source of diffusion
  */
function MixColumns(state) {
	let tmp = [...state];
	for(var i = 0; i < 4; i++) {
		tmp[0 * 4 + i] =  mul2[state[0 * 4 + i]] ^ mul3[state[1 * 4 + i]] ^ state[2 * 4 + i] ^ state[3 * 4 + i];
		tmp[1 * 4 + i] = state[0 * 4 + i] ^ mul2[state[1 * 4 + i]] ^ mul3[state[2 * 4 + i]] ^ state[3 * 4 + i];
		tmp[2 * 4 + i] = state[0 * 4 + i] ^ state[1 * 4 + i] ^ mul2[state[2 * 4 + i]] ^ mul3[state[3 * 4 + i]];
		tmp[3 * 4 + i] = mul3[state[0 * 4 + i]] ^ state[1 * 4 + i] ^ state[2 * 4 + i] ^ mul2[state[3 * 4 + i]];
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

	let state = []; // Stores the first 16 bytes of original message
	for (let i = 0; i < 4; i++) {
		for (let j = 0; j<4 ; j++){
			state[i+4*j] = message[i*4+j];
		}
	}
	let numberOfRounds = 9;
	AddRoundKey(state, expandedKey.slice(0, 16)); // Initial round

	for (let i = 1; i < numberOfRounds; i++) {
		Round(state, expandedKey.slice(16 * i, 16 * (i+1)));
	}

	FinalRound(state, expandedKey.slice(160,176));

    let encryptedMessage = [];
	// Copy encrypted state to buffer
	for (let i = 0; i < 16; i++) {
		encryptedMessage[i] = state[i];
	}
  return encryptedMessage;
}

/**
 * Triển khai hàm mã hóa (Encrypt function) <br>
	*	Chuyển đổi đầu vào thành dạng trạng thái (ma trận 4x4 byte). <br>
	*	Mở rộng khóa ban đầu thành mảng khóa. <br/>
	*	Thực hiện các vòng biến đổi:<br/>
	*	Vòng đầu tiên: AddRoundKey.<br/>
	*	Các vòng tiếp theo: SubBytes, ShiftRows, MixColumns, AddRoundKey.<br/>
	*	Vòng cuối cùng: SubBytes, ShiftRows, AddRoundKey.<br/>
	*	Kết quả là trạng thái sau cùng chính là văn bản đã mã hóa.<br/>
 */
export function AESEncrypt(message, key){
    let expandedKey = KeyExpansion(key);
	console.log(expandedKey);
		if(expandedKey && message) {
			let encryptedMessage = [];
			let paddedMessage = padMessage(message);
	
			for (let i = 0; i < paddedMessage.length; i += 16) {
				var block = paddedMessage.slice(i, i + 16);
				console.log(block);
				encryptedMessage.push(...AESEncryptBlock(block, expandedKey));
			}
			return encryptedMessage;
		} else {
			alert("message không hợp lệ");
			return null;
		}
}
