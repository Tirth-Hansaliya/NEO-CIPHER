// ciphers_classical_2.js - Algorithms 7 to 13
// Note: We'll link these appropriately in index.html

// 7. Vigenère Cipher
registerCipher({
    id: "vigenere",
    name: "7. Vigenère Cipher",
    category: "Classical Ciphers",
    description: "Polyalphabetic substitution using a repeating keyword and a Tabula Recta.",
    inputs: [
        { id: "text", type: "textarea", label: "Text" },
        { id: "key", type: "text", label: "Keyword" }
    ],
    encrypt: (inputs) => {
        let text = Utils.cleanAlpha(inputs.text);
        let key = Utils.cleanAlpha(inputs.key);
        if (!key) throw new Error("Key cannot be empty.");
        let res = "", steps = "";
        for(let i=0; i<text.length; i++) {
            let p = text.charCodeAt(i) - 65;
            let k = key.charCodeAt(i % key.length) - 65;
            let c = (p + k) % 26;
            res += String.fromCharCode(c + 65);
            steps += `${text[i]} + ${key[i%key.length]} -> ${res[i]}\n`;
        }
        return { result: res, steps: Utils.formatStep("Tabula Recta Additions", steps) };
    },
    decrypt: (inputs) => {
        let text = Utils.cleanAlpha(inputs.text);
        let key = Utils.cleanAlpha(inputs.key);
        let res = "", steps = "";
        for(let i=0; i<text.length; i++) {
            let c = text.charCodeAt(i) - 65;
            let k = key.charCodeAt(i % key.length) - 65;
            let p = Utils.mod((c - k), 26);
            res += String.fromCharCode(p + 65);
            steps += `${text[i]} - ${key[i%key.length]} -> ${res[i]}\n`;
        }
        return { result: res, steps: Utils.formatStep("Tabula Recta Subtractions", steps) };
    }
});

// 8. Vernam Cipher (OTP)
registerCipher({
    id: "vernam",
    name: "8. Vernam (One-Time Pad)",
    category: "Classical Ciphers",
    description: "XOR cipher over letters. Key must be equal length to text.",
    inputs: [
        { id: "text", type: "textarea", label: "Text (A-Z)" },
        { id: "key", type: "text", label: "Key (A-Z, length >= text)" }
    ],
    encrypt: (inputs) => {
        let text = Utils.cleanAlpha(inputs.text);
        let key = Utils.cleanAlpha(inputs.key);
        if (key.length < text.length) throw new Error("Key must be at least as long as the text.");
        let res="", steps="";
        for(let i=0; i<text.length; i++) {
            let p = text.charCodeAt(i) - 65;
            let k = key.charCodeAt(i) - 65;
            let c = p ^ k; // XOR
            // Map back to 0-25 using mod 26 since XOR might exceed 25. Actual OTP usually uses bits, but for classical char OTP we'll do (p ^ k) % 26 or just bitwise XOR modulo 26 or 32 mapped to A-Z. 
            // Better yet, classical Vernam cipher in letters usually does modulo 26 addition, but if they want XOR, let's just do binary XOR output or (p ^ k)%32 mapped back. Actually, standard char OTP is modulo 26 addition like Vigenere, or Bitwise XOR producing hex. Let's do Bitwise XOR and output Hex.
            let xorVal = text.charCodeAt(i) ^ key.charCodeAt(i);
            res += xorVal.toString(16).padStart(2, '0').toUpperCase() + " ";
            steps += `${text[i]} (${text.charCodeAt(i)}) XOR ${key[i]} (${key.charCodeAt(i)}) = ${xorVal.toString(16).toUpperCase()}\n`;
        }
        return { result: res.trim(), steps: Utils.formatStep("XOR Operations", steps) };
    },
    decrypt: (inputs) => {
        let tokens = inputs.text.trim().split(/\s+/);
        let key = Utils.cleanAlpha(inputs.key);
        if (key.length < tokens.length) throw new Error("Key must be at least as long as the text.");
        let res="", steps="";
        for(let i=0; i<tokens.length; i++) {
            let c = parseInt(tokens[i], 16);
            let p = c ^ key.charCodeAt(i);
            res += String.fromCharCode(p);
            steps += `${tokens[i]} XOR ${key[i]} (${key.charCodeAt(i)}) = ${String.fromCharCode(p)}\n`;
        }
        return { result: res, steps: Utils.formatStep("XOR Operations", steps) };
    }
});

// 9. Hill Cipher (2x2)
registerCipher({
    id: "hill",
    name: "9. Hill Cipher (2x2 Matrix)",
    category: "Classical Ciphers",
    description: "Polygraphic substitution using linear algebra and matrix multiplication modulo 26.",
    inputs: [
        { id: "text", type: "textarea", label: "Text" },
        { id: "key", type: "text", label: "4-Letter Key (forms 2x2 matrix)" }
    ],
    encrypt: (inputs) => {
        let text = Utils.cleanAlpha(inputs.text);
        let key = Utils.cleanAlpha(inputs.key);
        if (key.length !== 4) throw new Error("Key must be exactly 4 letters.");
        if (text.length % 2 !== 0) text += "X";
        
        let kMat = [ [key.charCodeAt(0)-65, key.charCodeAt(1)-65], [key.charCodeAt(2)-65, key.charCodeAt(3)-65] ];
        
        let res="", steps="Key Matrix:\n" + Utils.formatMatrix(kMat);
        for(let i=0; i<text.length; i+=2) {
            let p = [ [text.charCodeAt(i)-65], [text.charCodeAt(i+1)-65] ];
            let c = Utils.matrixMultMod(kMat, p, 26);
            res += String.fromCharCode(c[0][0] + 65) + String.fromCharCode(c[1][0] + 65);
        }
        return { result: res, steps: Utils.formatStep("Matrix Math", steps) };
    },
    decrypt: (inputs) => {
        let text = Utils.cleanAlpha(inputs.text);
        let key = Utils.cleanAlpha(inputs.key);
        if (key.length !== 4) throw new Error("Key must be exactly 4 letters.");
        if (text.length % 2 !== 0) throw new Error("Ciphertext length must be even.");
        
        let kMat = [ [key.charCodeAt(0)-65, key.charCodeAt(1)-65], [key.charCodeAt(2)-65, key.charCodeAt(3)-65] ];
        let kInv = Utils.inverse2x2Mod(kMat, 26);
        if (!kInv) throw new Error("Key matrix is not invertible mod 26.");
        
        let res="", steps="Inverse Key Matrix:\n" + Utils.formatMatrix(kInv);
        for(let i=0; i<text.length; i+=2) {
            let c = [ [text.charCodeAt(i)-65], [text.charCodeAt(i+1)-65] ];
            let p = Utils.matrixMultMod(kInv, c, 26);
            res += String.fromCharCode(p[0][0] + 65) + String.fromCharCode(p[1][0] + 65);
        }
        return { result: res, steps: Utils.formatStep("Matrix Math", steps) };
    }
});

// 10. Affine Cipher
registerCipher({
    id: "affine",
    name: "10. Affine Cipher",
    category: "Classical Ciphers",
    description: "C = (a*P + b) mod 26.",
    inputs: [
        { id: "text", type: "textarea", label: "Text" },
        { id: "a", type: "number", label: "Multiplier (a) - must be coprime to 26" },
        { id: "b", type: "number", label: "Shift (b)" }
    ],
    encrypt: (inputs) => {
        let text = Utils.cleanAlpha(inputs.text);
        let a = parseInt(inputs.a);
        let b = parseInt(inputs.b);
        if (Utils.gcd(a, 26) !== 1) throw new Error("'a' must be coprime to 26.");
        
        let res = "", steps="";
        for(let i=0; i<text.length; i++) {
            let p = text.charCodeAt(i) - 65;
            let c = (a * p + b) % 26;
            res += String.fromCharCode(c + 65);
            steps += `${text[i]} -> (${a}*${p} + ${b}) mod 26 = ${c} (${res[i]})\n`;
        }
        return { result: res, steps: Utils.formatStep("E(x) = (ax + b) mod 26", steps) };
    },
    decrypt: (inputs) => {
        let text = Utils.cleanAlpha(inputs.text);
        let a = parseInt(inputs.a);
        let b = parseInt(inputs.b);
        let aInv = Utils.modInverse(a, 26);
        if (!aInv) throw new Error("'a' has no modular inverse.");
        
        let res = "", steps="";
        for(let i=0; i<text.length; i++) {
            let c = text.charCodeAt(i) - 65;
            let p = Utils.mod(aInv * (c - b), 26);
            res += String.fromCharCode(p + 65);
            steps += `${text[i]} -> ${aInv}*(${c} - ${b}) mod 26 = ${p} (${res[i]})\n`;
        }
        return { result: res, steps: Utils.formatStep("D(x) = a^-1 (x - b) mod 26", steps) };
    }
});

// 11. Multiplicative Cipher
registerCipher({
    id: "multiplicative",
    name: "11. Multiplicative Cipher",
    category: "Classical Ciphers",
    description: "C = (a * P) mod 26.",
    inputs: [
        { id: "text", type: "textarea", label: "Text" },
        { id: "a", type: "number", label: "Multiplier (a) - must be coprime to 26" }
    ],
    encrypt: (inputs) => {
        // Just reuse Affine logic with b=0
        return CipherRegistry.list.find(c=>c.id==='affine').encrypt({...inputs, b: 0});
    },
    decrypt: (inputs) => {
        return CipherRegistry.list.find(c=>c.id==='affine').decrypt({...inputs, b: 0});
    }
});

// 12. Polyalphabetic Cipher
registerCipher({
    id: "polyalphabetic",
    name: "12. Polyalphabetic Cipher",
    category: "Classical Ciphers",
    description: "Uses a repeating set of numeric shifts (e.g. 5, 12, 3).",
    inputs: [
        { id: "text", type: "textarea", label: "Text" },
        { id: "shifts", type: "text", label: "Comma separated shifts (e.g., 5,12,3)" }
    ],
    encrypt: (inputs) => {
        let text = Utils.cleanAlpha(inputs.text);
        let shifts = inputs.shifts.split(',').map(s => parseInt(s.trim()));
        let res="", steps="";
        for(let i=0; i<text.length; i++) {
            let s = Utils.mod(shifts[i % shifts.length], 26);
            let p = text.charCodeAt(i) - 65;
            let c = (p + s) % 26;
            res += String.fromCharCode(c + 65);
            steps += `${text[i]} shifted by ${s} -> ${res[i]}\n`;
        }
        return { result: res, steps: Utils.formatStep("Shifts", steps) };
    },
    decrypt: (inputs) => {
        let text = Utils.cleanAlpha(inputs.text);
        let shifts = inputs.shifts.split(',').map(s => parseInt(s.trim()));
        let res="", steps="";
        for(let i=0; i<text.length; i++) {
            let s = Utils.mod(shifts[i % shifts.length], 26);
            let c = text.charCodeAt(i) - 65;
            let p = Utils.mod(c - s, 26);
            res += String.fromCharCode(p + 65);
            steps += `${text[i]} reverse shifted by ${s} -> ${res[i]}\n`;
        }
        return { result: res, steps: Utils.formatStep("Shifts", steps) };
    }
});

// 13. Frequency Analysis
registerCipher({
    id: "freq",
    name: "13. Frequency Analysis Tools",
    category: "Classical Ciphers",
    description: "Renders the frequency distribution of the input text.",
    inputs: [
        { id: "text", type: "textarea", label: "Input Text" }
    ],
    encrypt: (inputs) => {
        let text = Utils.cleanAlpha(inputs.text);
        let count = {};
        for(let i=0;i<text.length;i++){
            count[text[i]] = (count[text[i]]||0) + 1;
        }
        let steps = JSON.stringify(count, null, 2);
        return { result: text, steps: Utils.formatStep("Letter Counts", steps) };
    },
    decrypt: (inputs) => {
        return CipherRegistry.list.find(c=>c.id==='freq').encrypt(inputs);
    }
});
