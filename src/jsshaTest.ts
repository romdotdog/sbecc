import Sha256 from "jssha/dist/sha256";

const hash = new Sha256("SHA-256", "UINT8ARRAY");
hash.update("SHA256-TEST");
console.log(hash.getHash("UINT8ARRAY"));
