declare module "chacha20" {
	export class Cipher {
		constructor(key: ArrayBufferLike, nonce: ArrayBufferLike, counter: number);

		encrypt(dst: ArrayBufferLike, src: ArrayBufferLike, len: number): void;
	}
}
