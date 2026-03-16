// ciphers_modern.js - Algorithms 16 and 17

// 16. Modern Block Cipher (Simplified SPN Demo)
registerCipher({
    id: "spn",
    name: "16. Simplified SPN (Block Cipher Demo)",
    category: "Modern Ciphers",
    description: "Toy 16-bit Substitution-Permutation Network.",
    inputs: [
        { id: "text", type: "text", label: "Hexadecimal Input (e.g. 1A2B)" },
        { id: "key", type: "text", label: "Hexadecimal Key (e.g. 4F3D)" }
    ],
    encrypt: (inputs) => {
        let text = inputs.text.replace(/[^0-9A-Fa-f]/g, '').padEnd(4, '0').substring(0,4);
        let key = inputs.key.replace(/[^0-9A-Fa-f]/g, '').padEnd(4, '0').substring(0,4);
        
        let pBlock = parseInt(text, 16);
        let kBlock = parseInt(key, 16);
        
        // S-Box mapping (4-bit -> 4-bit)
        const sBox = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7];
        // P-Box mapping (16-bit 0-indexed)
        const pBox = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
        
        let steps = Utils.formatStep("Input", `Plaintext:  0x${text.toUpperCase()} (${pBlock.toString(2).padStart(16,'0')})\nKey:        0x${key.toUpperCase()} (${kBlock.toString(2).padStart(16,'0')})`);
        
        // Step 1: AddRoundKey (XOR)
        let state = pBlock ^ kBlock;
        steps += Utils.formatStep("AddRoundKey", `State = P XOR K\nState: ${state.toString(2).padStart(16,'0')} (0x${state.toString(16).toUpperCase()})`);
        
        // Step 2: Substitution Network
        let subState = 0;
        for(let i=0; i<4; i++) {
            let nibble = (state >> (i*4)) & 0xF;
            let subNibble = sBox[nibble];
            subState |= (subNibble << (i*4));
        }
        steps += Utils.formatStep("Substitution (S-Box)", `SubState: ${subState.toString(2).padStart(16,'0')} (0x${subState.toString(16).toUpperCase()})`);
        
        // Step 3: Permutation Network
        let permState = 0;
        for(let i=0; i<16; i++) {
            let bit = (subState >> i) & 1;
            permState |= (bit << pBox[i]);
        }
        steps += Utils.formatStep("Permutation (P-Box)", `PermState: ${permState.toString(2).padStart(16,'0')} (0x${permState.toString(16).toUpperCase()})`);
        
        let resultHex = permState.toString(16).padStart(4, '0').toUpperCase();
        return { result: resultHex, steps };
    },
    decrypt: (inputs) => {
        let text = inputs.text.replace(/[^0-9A-Fa-f]/g, '').padEnd(4, '0').substring(0,4);
        let key = inputs.key.replace(/[^0-9A-Fa-f]/g, '').padEnd(4, '0').substring(0,4);
        
        let cBlock = parseInt(text, 16);
        let kBlock = parseInt(key, 16);
        
        const sBoxInv = [14, 3, 4, 8, 1, 12, 10, 15, 7, 13, 9, 6, 11, 2, 0, 5];
        const pBoxInv = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]; // happens to be its own inverse
        
        let steps = Utils.formatStep("Input", `Ciphertext: 0x${text.toUpperCase()} (${cBlock.toString(2).padStart(16,'0')})\nKey:        0x${key.toUpperCase()}`);
        
        // Reverse P-Box
        let permState = 0;
        for(let i=0; i<16; i++) {
            let bit = (cBlock >> i) & 1;
            permState |= (bit << pBoxInv[i]);
        }
        steps += Utils.formatStep("Inverse Permutation", `State: ${permState.toString(2).padStart(16,'0')} (0x${permState.toString(16).toUpperCase()})`);
        
        // Reverse S-Box
        let subState = 0;
        for(let i=0; i<4; i++) {
            let nibble = (permState >> (i*4)) & 0xF;
            let subNibble = sBoxInv[nibble];
            subState |= (subNibble << (i*4));
        }
        steps += Utils.formatStep("Inverse Substitution", `State: ${subState.toString(2).padStart(16,'0')} (0x${subState.toString(16).toUpperCase()})`);
        
        // Reverse AddRoundKey (XOR)
        let state = subState ^ kBlock;
        steps += Utils.formatStep("Inverse AddRoundKey", `P = State XOR K\nState: ${state.toString(2).padStart(16,'0')} (0x${state.toString(16).toUpperCase()})`);
        
        let resultHex = state.toString(16).padStart(4, '0').toUpperCase();
        return { result: resultHex, steps };
    }
});

// 17. Linear Feedback Shift Register (Stream Cipher)
registerCipher({
    id: "lfsr",
    name: "17. LFSR Stream Cipher Demo",
    category: "Modern Ciphers",
    description: "Generates a pseudorandom keystream using an LFSR, then XORs with plaintext.",
    inputs: [
        { id: "text", type: "text", label: "Binary Data (e.g. 10101100)" },
        { id: "seed", type: "text", label: "LFSR Seed (e.g. 1001)" },
        { id: "taps", type: "text", label: "Taps (comma separated, e.g. 4,3 for x^4 + x^3 + 1)" }
    ],
    encrypt: (inputs) => {
        let text = inputs.text.replace(/[^01]/g, '');
        let seed = inputs.seed.replace(/[^01]/g, '');
        let taps = inputs.taps.split(',').map(n => parseInt(n.trim()));
        
        if (!text || !seed || taps.length === 0) throw new Error("Invalid binary inputs.");
        
        let lfsrSize = seed.length;
        // convert seed to array of ints
        let reg = seed.split('').map(x => parseInt(x));
        
        let keystream = "";
        let steps = Utils.formatStep("Initial Setup", `Data: ${text}\nSeed: ${seed}\nTaps: [${taps.join(', ')}]`);
        let shiftLog = "LFSR Shifts:\n";
        
        for(let i=0; i<text.length; i++) {
            // output is the last bit
            let bitOut = reg[lfsrSize - 1];
            keystream += bitOut;
            
            // calc feedback (XOR of tapped bits, 1-indexed)
            let feedback = 0;
            for(let t of taps) {
                // if tap is 4, index is 3 (size-4 = 0? Wait, normally tap 4 means bit 4 from left or right?
                // Let's assume standard right-to-left: tap 1 is rightmost.
                feedback ^= reg[lfsrSize - t];
            }
            
            shiftLog += `[${reg.join('')}] -> Out: ${bitOut}, Feed: ${feedback}\n`;
            
            // shift right
            for(let j=lfsrSize-1; j>0; j--) {
                reg[j] = reg[j-1];
            }
            reg[0] = feedback;
        }
        
        steps += Utils.formatStep("Keystream Generation", shiftLog);
        steps += Utils.formatStep("XOR Process", `Data:      ${text}\nKeystream: ${keystream}`);
        
        let res = "";
        for(let i=0; i<text.length; i++) {
            res += (parseInt(text[i]) ^ parseInt(keystream[i])) ? "1" : "0";
        }
        
        return { result: res, steps: steps + Utils.formatStep("Result", res) };
    },
    decrypt: (inputs) => {
        // Stream Cipher XOR decryption is identical to encryption
        return CipherRegistry.list.find(c=>c.id==='lfsr').encrypt(inputs);
    }
});
