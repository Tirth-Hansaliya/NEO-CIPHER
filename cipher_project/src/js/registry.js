// registry.js
// Stores all 23 cipher configurations and references to their encrypt/decrypt methods.

const CipherRegistry = {
    categories: [
        "Classical Ciphers",
        "Transposition Ciphers",
        "Modern Ciphers",
        "Asymmetric Ciphers",
        "Symmetric Standards"
    ],
    list: []
};

// Helper to register a cipher
function registerCipher(config) {
    CipherRegistry.list.push(config);
}

// Will be populated by individual cipher files:
// config = {
//   id: "caesar",
//   name: "1. Caesar Cipher",
//   category: "Classical Ciphers",
//   description: "Additive substitution cipher.",
//   inputs: [
//       { id: "text", type: "textarea", label: "Text (Plaintext / Ciphertext)" },
//       { id: "shift", type: "number", label: "Shift Key (e.g., 3)" }
//   ],
//   encrypt: (inputs) => { return { result: "XYZ", steps: "Step 1..." }; },
//   decrypt: (inputs) => { return { result: "ABC", steps: "Step 1..." }; }
// }
