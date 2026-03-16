// ciphers_classical.js - Algorithms 1 to 13
// 1. Caesar Cipher
registerCipher({
    id: "caesar",
    name: "1. Caesar Cipher (Additive)",
    category: "Classical Ciphers",
    description: "Shifts letters by a fixed number. Key is the shift value.",
    inputs: [
        { id: "text", type: "textarea", label: "Text" },
        { id: "shift", type: "number", label: "Shift Key (e.g., 3)" }
    ],
    encrypt: (inputs) => {
        let text = Utils.cleanAlpha(inputs.text);
        let shift = Utils.mod(inputs.shift, 26);
        let result = "";
        let steps = Utils.formatStep("Input Analysis", `Plaintext: ${text}\nShift: ${shift}`);
        
        for (let i = 0; i < text.length; i++) {
            let p = text.charCodeAt(i) - 65;
            let c = (p + shift) % 26;
            result += String.fromCharCode(c + 65);
        }
        steps += Utils.formatStep("Encryption Steps", `C = (P + ${shift}) mod 26\nResult: ${result}`);
        return { result, steps };
    },
    decrypt: (inputs) => {
        let text = Utils.cleanAlpha(inputs.text);
        let shift = Utils.mod(inputs.shift, 26);
        let result = "";
        let steps = Utils.formatStep("Input Analysis", `Ciphertext: ${text}\nShift: ${shift}`);
        
        for (let i = 0; i < text.length; i++) {
            let c = text.charCodeAt(i) - 65;
            let p = Utils.mod(c - shift, 26);
            result += String.fromCharCode(p + 65);
        }
        steps += Utils.formatStep("Decryption Steps", `P = (C - ${shift}) mod 26\nResult: ${result}`);
        return { result, steps };
    }
});

// 2. Monoalphabetic Cipher
registerCipher({
    id: "mono",
    name: "2. Monoalphabetic Cipher",
    category: "Classical Ciphers",
    description: "Substitutes letters according to a custom 26-letter alphabet.",
    inputs: [
        { id: "text", type: "textarea", label: "Text" },
        { id: "key", type: "text", label: "Substitution Alphabet (26 unique letters)", placeholder: "QWERTYUIOPASDFGHJKLZXCVBNM" }
    ],
    encrypt: (inputs) => {
        let text = Utils.cleanAlpha(inputs.text);
        let key = Utils.cleanAlpha(inputs.key);
        if (key.length !== 26) throw new Error("Key must be exactly 26 letters.");
        if (new Set(key.split('')).size !== 26) throw new Error("Key must have unique letters.");
        
        let result = "";
        for (let i=0; i<text.length; i++) {
            result += key[text.charCodeAt(i) - 65];
        }
        return { 
            result, 
            steps: Utils.formatStep("Key Mapping", `A-Z -> ${key}\nMapped char-by-char.`) 
        };
    },
    decrypt: (inputs) => {
        let text = Utils.cleanAlpha(inputs.text);
        let key = Utils.cleanAlpha(inputs.key);
        if (key.length !== 26) throw new Error("Key must be exactly 26 letters.");
        let std = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let map = {};
        for(let i=0; i<26; i++) map[key[i]] = std[i];
        
        let result = "";
        for(let i=0; i<text.length; i++) result += map[text[i]];
        return { result, steps: Utils.formatStep("Reverse Mapping", `Key -> A-Z.\nMapped char-by-char.`) };
    }
});



// --- Group Playfair Generators ---
function generatePlayfairMatrix(key, alphabet, size) {
    let clean = (key + alphabet)
        .toUpperCase()
        .replace(/[^A-Z0-9!@#$%^&*]/g, "");
    
    // Remove J for standard 5x5 if alphabet is A-Z sans J
    if (size === 25) clean = clean.replace(/J/g, "I");
    
    let seen = new Set();
    let mat = [];
    let r = [];
    for (let c of clean) {
        if (!seen.has(c)) {
            seen.add(c);
            r.push(c);
            if (r.length === Math.sqrt(size)) {
                mat.push(r);
                r = [];
            }
        }
    }
    return mat;
}

function processPlayfair(text, mat, isEncrypt) {
    let size = mat.length;
    // Map chars to positions
    let pos = {};
    for(let i=0; i<size; i++) {
        for(let j=0; j<size; j++) {
            pos[mat[i][j]] = {r:i, c:j};
        }
    }
    
    // Prep text (digraphs)
    let pText = "";
    if (isEncrypt) {
        for(let i=0; i<text.length; i++) {
            pText += text[i];
            if (i+1 < text.length && text[i] === text[i+1]) {
                pText += "X";
            }
        }
        if (pText.length % 2 !== 0) pText += "X";
    } else {
        pText = text;
    }
    
    let result = "";
    let stepLog = "";
    let shift = isEncrypt ? 1 : -1;
    
    for(let i=0; i<pText.length; i+=2) {
        let a = pText[i], b = pText[i+1];
        if(!pos[a] || !pos[b]) {
            result += a+b; continue;
        }
        let pa = pos[a], pb = pos[b];
        
        if (pa.r === pb.r) {
            result += mat[pa.r][Utils.mod(pa.c + shift, size)] + mat[pb.r][Utils.mod(pb.c + shift, size)];
        } else if (pa.c === pb.c) {
            result += mat[Utils.mod(pa.r + shift, size)][pa.c] + mat[Utils.mod(pb.r + shift, size)][pb.c];
        } else {
            result += mat[pa.r][pb.c] + mat[pb.r][pa.c];
        }
        stepLog += `${a}${b} -> ${result.slice(-2)}\n`;
    }
    return { result, stepLog };
}

// 4. Playfair Cipher
registerCipher({
    id: "playfair",
    name: "4. Playfair Cipher (5x5)",
    category: "Classical Ciphers",
    description: "Digraph substitution using a 5x5 matrix (I/J combined).",
    inputs: [
        { id: "text", type: "textarea", label: "Text" },
        { id: "key", type: "text", label: "Keyword" }
    ],
    encrypt: (inputs) => {
        let mat = generatePlayfairMatrix(inputs.key, "ABCDEFGHIKLMNOPQRSTUVWXYZ", 25);
        let text = Utils.cleanAlpha(inputs.text).replace(/J/g, "I");
        let res = processPlayfair(text, mat, true);
        return { result: res.result, steps: Utils.formatStep("Matrix", Utils.formatMatrix(mat)) + Utils.formatStep("Pairs", res.stepLog) };
    },
    decrypt: (inputs) => {
        let mat = generatePlayfairMatrix(inputs.key, "ABCDEFGHIKLMNOPQRSTUVWXYZ", 25);
        let text = Utils.cleanAlpha(inputs.text);
        let res = processPlayfair(text, mat, false);
        return { result: res.result, steps: Utils.formatStep("Matrix", Utils.formatMatrix(mat)) + Utils.formatStep("Pairs", res.stepLog) };
    }
});

// 5. Alphanumeric Playfair
registerCipher({
    id: "playfair6x6",
    name: "5. Alphanumeric Playfair (6x6)",
    category: "Classical Ciphers",
    description: "Playfair applied to a 6x6 matrix (A-Z, 0-9).",
    inputs: [
        { id: "text", type: "textarea", label: "Text" },
        { id: "key", type: "text", label: "Keyword" }
    ],
    encrypt: (inputs) => {
        let mat = generatePlayfairMatrix(inputs.key, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 36);
        let text = inputs.text.toUpperCase().replace(/[^A-Z0-9]/g, "");
        let res = processPlayfair(text, mat, true);
        return { result: res.result, steps: Utils.formatStep("Matrix", Utils.formatMatrix(mat)) + Utils.formatStep("Pairs", res.stepLog) };
    },
    decrypt: (inputs) => {
        let mat = generatePlayfairMatrix(inputs.key, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 36);
        let text = inputs.text.toUpperCase().replace(/[^A-Z0-9]/g, "");
        let res = processPlayfair(text, mat, false);
        return { result: res.result, steps: Utils.formatStep("Matrix", Utils.formatMatrix(mat)) + Utils.formatStep("Pairs", res.stepLog) };
    }
});

// 6. Extended Playfair
registerCipher({
    id: "playfair8x8",
    name: "6. Extended Playfair (8x8)",
    category: "Classical Ciphers",
    description: "Playfair grid expanded to 8x8 (64 chars) to include a-z, A-Z, 0-9 and common symbols.",
    inputs: [
        { id: "text", type: "textarea", label: "Text" },
        { id: "key", type: "text", label: "Keyword" }
    ],
    // Let's use custom uppercase + lowercase + symbols for 8x8
    encrypt: (inputs) => {
        let charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@";
        let text = inputs.text.replace(/[^A-Za-z0-9!@]/g, "");
        let mat = generatePlayfairMatrix(inputs.key, charset, 64);
        let res = processPlayfair(text, mat, true);
        return { result: res.result, steps: Utils.formatStep("Matrix", Utils.formatMatrix(mat)) + Utils.formatStep("Pairs", res.stepLog) };
    },
    decrypt: (inputs) => {
        let charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@";
        let text = inputs.text.replace(/[^A-Za-z0-9!@]/g, "");
        let mat = generatePlayfairMatrix(inputs.key, charset, 64);
        let res = processPlayfair(text, mat, false);
        return { result: res.result, steps: Utils.formatStep("Matrix", Utils.formatMatrix(mat)) + Utils.formatStep("Pairs", res.stepLog) };
    }
});
