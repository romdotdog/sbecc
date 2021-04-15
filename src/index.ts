import secp256k1 from "secp256k1";
import { randomBytes } from "crypto";
import Sha256 from "jssha/dist/sha256";
import { Cipher as Chacha20 } from "chacha20";

function toBytes(x: string) {
	const length = x.length / 2;
	const bytes = new Uint8Array(length);
	for (let i = 0; i < length; i++) {
		const i2 = i * 2;
		bytes[i] = parseInt(x.substring(i2, i2 + 2), 16);
	}
	return bytes;
}

function getPrivateKey() {
	while (true) {
		const privKey = randomBytes(32);
		if (secp256k1.privateKeyVerify(privKey)) return privKey;
	}
}

// Public keys:
// 04f9677f2dcfa326d5339a247c5ae00b1161fbc6207e37d0ab45da45c1475f28385d9a853b61df9dd34b54b2fea3cd189b9bbbeb1d391c69ab17dec505acdbd859
// 03f9677f2dcfa326d5339a247c5ae00b1161fbc6207e37d0ab45da45c1475f2838

const serverPublicKey = toBytes(
	"04f9677f2dcfa326d5339a247c5ae00b1161fbc6207e37d0ab45da45c1475f28385d9a853b61df9dd34b54b2fea3cd189b9bbbeb1d391c69ab17dec505acdbd859"
);

function getXY(combined: Uint8Array): [X: Uint8Array, Y: Uint8Array] {
	return [combined.subarray(1, 33), combined.subarray(33, 65)];
}

function encrypt(text: string) {
	const privKey = getPrivateKey();
	const pubKey = secp256k1.publicKeyCreate(privKey, false);
	const [pubX, pubY] = getXY(pubKey);

	// Get shared key
	const sharedKey = secp256k1.publicKeyTweakMul(
		serverPublicKey,
		privKey,
		false
	);

	// Extract X and Y
	const [sharedX, sharedY] = getXY(sharedKey);
	const HMACKey = new Uint8Array(64);
	HMACKey.set(sharedX, 0);
	HMACKey.set(sharedY, 32);

	const chachaKeySha = new Sha256("SHA-256", "TEXT");
	chachaKeySha.setHMACKey(HMACKey, "UINT8ARRAY");
	chachaKeySha.update("rom x turtsis");

	const data = new TextEncoder().encode(text); // for future isomorphism
	const key = chachaKeySha.getHMAC("UINT8ARRAY");
	const nonce = new Uint8Array(randomBytes(12));

	const cipher = new Chacha20(key, nonce, 1);
	const encryptedText = new Uint8Array(data.length);
	cipher.encrypt(encryptedText, data, data.length);

	// Construct bytestring
	/*
		pubKeyX, / 32 bytes,
		pubKeyY, / 32 bytes
		nonce, / 12 bytes,
		ChaCha20-ciphered script / rest of bytes
	*/

	const result = new Uint8Array(76 + encryptedText.length);
	result.set(pubX, 0);
	result.set(pubY, 32);
	result.set(nonce, 64);
	result.set(encryptedText, 76);

	// https://stackoverflow.com/questions/39225161/convert-uint8array-into-hex-string-equivalent-in-node-js
	return result.reduce(
		(str: string, i) => str + ("0" + i.toString(16)).slice(-2),
		""
	);
}

console.log(encrypt("for i,v in pairs({'hello', 'world'}) do print(v) end"));
