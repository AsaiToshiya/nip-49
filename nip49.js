const { XChaCha20Poly1305 } = require("@stablelib/xchacha20poly1305");
const scrypt = require("scrypt-js");
const { bech32 } = require("@scure/base");
const { randomBytes } = require("@stablelib/random");

const deriveSymmetricKey = (passphrase, salt, logN) => {
  const N = Math.pow(2, logN);
  const r = 8;
  const p = 1;
  const keyLength = 32;

  const passphraseBuffer = Buffer.from(passphrase);

  return scrypt.scrypt(passphraseBuffer, salt, N, r, p, keyLength);
};

const encrypt = async (privateKeyHex, passphrase, logN) => {
  const privateKey = Uint8Array.from(Buffer.from(privateKeyHex, "hex"));

  const salt = randomBytes(16);
  const nonce = randomBytes(24);
  const associatedData = new Uint8Array([0x02]);

  const symmetricKey = await deriveSymmetricKey(passphrase, salt, logN);
  const aead = new XChaCha20Poly1305(symmetricKey);
  const ciphertext = aead.seal(nonce, privateKey, associatedData);

  const data = bech32.toWords(
    new Uint8Array([
      0x02,
      logN,
      ...salt,
      ...nonce,
      ...associatedData,
      ...ciphertext,
    ])
  );
  return bech32.encode("ncryptsec", data, false);
};

const decrypt = async (encryptedKey, passphrase) => {
  const { words } = bech32.decode(encryptedKey, false);
  const data = bech32.fromWords(words);

  const logN = data[1];
  const salt = data.slice(2, 18);
  const nonce = data.slice(18, 42);
  const associatedData = data.slice(42, 43);
  const ciphertext = data.slice(43);

  const symmetricKey = await deriveSymmetricKey(passphrase, salt, logN);
  const aead = new XChaCha20Poly1305(symmetricKey);
  const decryptedKey = aead.open(nonce, ciphertext, associatedData);

  return Buffer.from(decryptedKey).toString("hex");
};

module.exports = {
  encrypt,
  decrypt,
};
