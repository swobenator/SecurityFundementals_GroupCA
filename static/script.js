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
