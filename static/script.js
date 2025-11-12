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

// ===== RSA Key Decryption ===== Edvin Krasovski
function rsaDecryptKeyBlocks(cipherBlocks, privateKey) {
    //Extract private exponent (d) and modulus (n) from the private key
    const { d, n } = privateKey;
    //Initialize an empty array to store decrypted character codes
    let chars = [];
    //Iterate through each encrypted block in the cipherBlocks array
    for (let c of cipherBlocks) {
        //Convert the cipher block to BigInt for modular arithmetic
        const cBig = BigInt(c);
        //Perform RSA decryption: m = c^d mod n
        const m = modPow(cBig, d, n);
        //Convert the decrypted numeric value to a character and store it
        chars.push(String.fromCharCode(Number(m)));
    }
    //Join all decrypted characters into a single string and return it
    return chars.join('');
}

// ===== DOM Helpers ===== Edvin Krasovski
const messageList = document.getElementById('messageList');

function appendMessage(text, cls='other') {
    //Create a new div element for the message
    const d = document.createElement('div');
    //Assign the message CSS class (default is 'other')
    d.className = 'msg ' + cls;
    //Set the message text content
    d.textContent = text;
    //Append the message element to the message list
    messageList.appendChild(d);
    //Scroll to the bottom to show the latest message
    messageList.scrollTop = messageList.scrollHeight;
}

function appendSystem(text) {
    //Create a new div element for the system message
    const d = document.createElement('div');
    //Assign the 'system' CSS class for system messages
    d.className = 'msg system';
    //Set the system message text content
    d.textContent = text;
    //Append the system message to the message list
    messageList.appendChild(d);
    //Scroll to the bottom to ensure visibility of the latest message
    messageList.scrollTop = messageList.scrollHeight;
}


// ===== Socket.IO connection ===== Soheib Ameur
// Establish a connection between the client and the Flask Socket.IO server
const socket = io.connect(SERVER_URL);

// Event listener triggered when the connection to the server is successfully established
socket.on('connect', () => appendSystem("Connected to server."));

// Event listener triggered when the client is disconnected from the server
socket.on('disconnect', () => appendSystem("Disconnected."));

// ===== Private Key Handling ===== Soheib Ameur
// The RSA private key is automatically provided by the server and injected into the global variable
// window.SERVER_PRIVATE_KEY (passed from Flask template context).
// This allows the client to perform RSA decryption without user interaction.
let PRIVATE_KEY = {
  d: BigInt(window.SERVER_PRIVATE_KEY.d),  // RSA private exponent (used for decryption)
  n: BigInt(window.SERVER_PRIVATE_KEY.n)   // RSA modulus (product of two primes)
};

// ===== Receive Encrypted Messages ===== Edvin Krasovski
// This listener waits for messages sent from the server under the event name defined in EVENT_RECEIVE.
// The message payload includes the Vigenere ciphertext and RSA-encrypted key blocks.
socket.on(EVENT_RECEIVE, data => {
  try {
    // Extract the encrypted message and RSA key blocks from thepayload
    const vig_cipher = data.vig_ciphertext;     // The Vigenere-encrypted message
    const rsa_blocks = data.rsa_key_blocks;     // RSA-encrypted Vigenère key (as list of integers)

    // Step 1: Dcrypt the RSA blocks using the local private key
    // This recovers the original plaintext Vigenère key
    const vig_key_plain = rsaDecryptKeyBlocks(rsa_blocks, PRIVATE_KEY);

    // Step 2: Use the recovered Vigenère key to decrypt the ciphertext
    // produces the readable plaintext message
    const plaintext = decryptVigenere(vig_cipher, vig_key_plain);

    // Display both the encrypted and decrypted versions in the chat window for comparison
    appendMessage("Encrypted: " + vig_cipher, 'other');
    appendMessage("Decrypted: " + plaintext, 'other');
  } catch (e) {
    // If decryption fails (invalid key or malformed data), show an error
    appendSystem("Decryption error.");
  }
});

// ===== Send Plaintext Messages ===== Soheib Ameur
// Locate the "Send" button and attach an event listener for click events
const sendBtn = document.getElementById('sendBtn');
sendBtn.addEventListener('click', () => {
  // Retrieve the message from the input field and trim any extra spaces
  const msg = document.getElementById('messageInput').value.trim();

  // Do nothing if the message is empty
  if (!msg) return;

  // Emit the message to the server through theEVENT_SEND channel
  // The server handles encryption and broadcasts it to all clients
  socket.emit(EVENT_SEND, { message: msg });

  // Immediately show the user's own message in the chat window
  appendMessage(msg, 'you');

  // Clear the input box after sending
  document.getElementById('messageInput').value = '';
});

// ===== Keyboard Shortcut for Sending ===== Soheib Ameur
// Adds a keyboard shortcut: pressing Ctrl +Enter (or Cmd+Enter on macOS)
// sends the message without clicking the Send button manually
document.getElementById('messageInput').addEventListener('keydown', e => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) sendBtn.click();
});
