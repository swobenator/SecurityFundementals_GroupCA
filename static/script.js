// ===== Configuration ===== Soheib Ameur
const SERVER_URL = "http://localhost:3000";
const EVENT_SEND = "send_message";
const EVENT_RECEIVE = "receive_message";

// ===== Utility: Modular exponentiation (RSA) ===== Edvin Krasovski
function modPow(base, exponent, modulus) {
    //Converts inputs to BigInt and reduces base modulo modulus
    base = BigInt(base) % BigInt(modulus);
    exponent = BigInt(exponent);
    modulus = BigInt(modulus);
    //If modulus is 1, result is always 0 (since anything mod 1 = 0)
    if (modulus === 1n) return 0n;
    //Initialize result to 1 (identity element for multiplication)
    let result = 1n;
    //Loop until all bits of exponent are processed
    while (exponent > 0n) {
        //If the current bit of exponent is 1, multiply result by base modulo modulus
        if (exponent & 1n) result = (result * base) % modulus;
        //Shift exponent right by 1 bit (equivalent to dividing by 2)
        exponent >>= 1n;
        //Square the base modulo modulus (exponentiation by squaring)
        base = (base * base) % modulus;
    }
    //Return the final modular exponentiation result
    return result;
}


// ===== Vigenère Decryption ===== Soheib Ameur
function createKey(message, key) {
  // If the key is already long enough, trim it
  if (key.length >= message.length) return key.slice(0, message.length);

  // Convert the key into an array of characters
  let result = key.split('');
  const originalLength = key.length;
  let i = 0;

  // Repeat key characters cyclically until it matches message length
  while (result.length < message.length) {
    result.push(key[i % originalLength]);
    i++;
  }

  // Join array back into a single string and return
  return result.join('');
}

function decryptVigenere(ciphertext, key) {
  // Extend or trim the key to match the ciphertext length
  const keyStream = createKey(ciphertext, key);
  let out = [];

  // Loop through each character in the ciphertext
  for (let i = 0; i < ciphertext.length; i++) {
    const ch = ciphertext[i];           // Current ciphertext character
    const kch = keyStream[i].toUpperCase(); // Corresponding key character (converted to uppercase)

    // If character is uppercase letter (A–Z)
    if (ch >= 'A' && ch <= 'Z') {
      const a = ch.charCodeAt(0) - 65;  // Convert letter to 0–25 index
      const b = kch.charCodeAt(0) - 65; // Convert key letter to 0–25 index
      // Perform reverse Caesar shift (subtract key value)
      out.push(String.fromCharCode((a - b + 26) % 26 + 65));

    // If character is lowercase letter (a–z)
    } else if (ch >= 'a' && ch <= 'z') {
      const a = ch.charCodeAt(0) - 97;
      const b = kch.charCodeAt(0) - 65; // still uppercase for consistency
      out.push(String.fromCharCode((a - b + 26) % 26 + 97));

    // If character is non-alphabetic (spaces, punctuation, numbers), keep as is
    } else out.push(ch);
  }

  // Join the decrypted characters into a final string
  return out.join('');
}
