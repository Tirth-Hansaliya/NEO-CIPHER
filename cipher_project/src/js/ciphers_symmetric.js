// ciphers_symmetric.js - Algorithms 22 and 23

// --- DES Tables & Helpers ---
const DES_IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
];
const DES_FP = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25
];
const DES_E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
];
const DES_P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
];
const DES_PC1 = [
    57, 49, 41, 33, 25, 17, 9,  1, 58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7,  62, 54, 46, 38, 30, 22, 14, 6,  61, 53, 45, 37,
    29, 21, 13, 5,  28, 20, 12, 4
];
const DES_PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 
    26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
];
const DES_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

const DES_SBOX = [
    // S1
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
    ],
    // S2
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
    ],
    // S3
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
    ],
    // S4
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
    ],
    // S5
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
    ],
    // S6
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
    ],
    // S7
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
    ],
    // S8
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
    ]
];

function permuteDES(inputHex, pTable, outBits) {
    let binStr = "";
    for(let i=0; i<inputHex.length; i++) {
        binStr += parseInt(inputHex[i], 16).toString(2).padStart(4, '0');
    }
    // ensure enough padding
    binStr = binStr.padStart(Math.max(binStr.length, Math.max(...pTable)), '0');
    
    let res = "";
    for(let i=0; i<outBits; i++) {
        res += binStr[pTable[i] - 1]; // tables are 1-indexed
    }
    // return binary string
    return res;
}

function hexToBin(hex, length) {
    let bin = "";
    for(let i=0; i<hex.length; i++) {
        bin += parseInt(hex[i], 16).toString(2).padStart(4, '0');
    }
    return bin.padStart(length, '0').slice(-length);
}

function binToHex(bin) {
    let hex = "";
    for(let i=0; i<bin.length; i+=4) {
        hex += parseInt(bin.substr(i, 4), 2).toString(16).toUpperCase();
    }
    return hex;
}

function leftShiftStr(str, n) {
    return str.substring(n) + str.substring(0, n);
}

function xorBin(a, b) {
    let res = "";
    for(let i=0; i<a.length; i++) {
        res += (a[i] === b[i]) ? "0" : "1";
    }
    return res;
}

function sboxSubstitute(bin) {
    let res = "";
    for(let i=0; i<8; i++) {
        let chunk = bin.substr(i*6, 6);
        let row = parseInt(chunk[0] + chunk[5], 2);
        let col = parseInt(chunk.substring(1, 5), 2);
        let val = DES_SBOX[i][row * 16 + col];
        res += val.toString(2).padStart(4, '0');
    }
    return res;
}

function runDES(textHex, keyHex, isEncrypt) {
    let stepsLog = "";
    
    // Key schedule
    let keyBin = hexToBin(keyHex, 64);
    let pc1Key = permuteDES(binToHex(keyBin), DES_PC1, 56);
    let C = pc1Key.substring(0, 28);
    let D = pc1Key.substring(28, 56);
    
    let roundKeys = [];
    stepsLog += Utils.formatStep("Key Schedule Setup", `Original Key (Hex): ${keyHex}\nPC-1 Key (Binary): ${pc1Key}`);
    
    for(let i=0; i<16; i++) {
        C = leftShiftStr(C, DES_SHIFTS[i]);
        D = leftShiftStr(D, DES_SHIFTS[i]);
        let kBin = permuteDES(binToHex(C+D), DES_PC2, 48);
        roundKeys.push(kBin);
    }
    
    if (!isEncrypt) {
        roundKeys.reverse();
    }
    
    // IP
    let ipBin = permuteDES(textHex, DES_IP, 64);
    let L = ipBin.substring(0, 32);
    let R = ipBin.substring(32, 64);
    stepsLog += Utils.formatStep("Initial Permutation (IP)", `L0: ${L}\nR0: ${R}`);
    
    for(let i=0; i<16; i++) {
        let prevL = L, prevR = R;
        L = prevR;
        
        let eR = permuteDES(binToHex(prevR), DES_E, 48);
        let xr = xorBin(eR, roundKeys[i]);
        let sr = sboxSubstitute(xr);
        let pR = permuteDES(binToHex(sr), DES_P, 32);
        
        R = xorBin(prevL, pR);
        
        stepsLog += Utils.formatStep(`Round ${i+1}`, `K${i+1}: ${binToHex(roundKeys[i])}\nE(R): ${binToHex(eR)}\nSBoxOut: ${binToHex(sr)}\nP(Output): ${binToHex(pR)}\nL${i+1}: ${L} (0x${binToHex(L)})\nR${i+1}: ${R} (0x${binToHex(R)})`);
    }
    
    // Final swap
    let RL = R + L;
    let fp = permuteDES(binToHex(RL), DES_FP, 64);
    let resHex = binToHex(fp);
    stepsLog += Utils.formatStep("Final Permutation (IP inverse)", `Input RL: 0x${binToHex(RL)}\nOutput: 0x${resHex}`);
    
    return { result: resHex, steps: stepsLog };
}

registerCipher({
    id: "des",
    name: "22. DES (Data Encryption Standard)",
    category: "Symmetric Standards",
    description: "64-bit block cipher using 56-bit key. Displays full 16 rounds with Feistel network steps.",
    inputs: [
        { id: "text", type: "text", label: "Data Block (16 Hex Digits)", placeholder: "0123456789ABCDEF" },
        { id: "key", type: "text", label: "Key (16 Hex Digits)", placeholder: "133457799BBCDFF1" }
    ],
    encrypt: (inputs) => runDES(inputs.text.padEnd(16, '0').slice(0, 16), inputs.key.padEnd(16, '0').slice(0, 16), true),
    decrypt: (inputs) => runDES(inputs.text.padEnd(16, '0').slice(0, 16), inputs.key.padEnd(16, '0').slice(0, 16), false)
});

// --- AES Helpers ---
const AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 
];
const AES_INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
];
// standard RCON
const Rcon = [
    [0x00, 0, 0, 0],
    [0x01, 0, 0, 0], [0x02, 0, 0, 0], [0x04, 0, 0, 0], [0x08, 0, 0, 0],
    [0x10, 0, 0, 0], [0x20, 0, 0, 0], [0x40, 0, 0, 0], [0x80, 0, 0, 0],
    [0x1b, 0, 0, 0], [0x36, 0, 0, 0]
];

function gfMul(a, b) {
    let p = 0;
    let hiBitSet;
    for (let i = 0; i < 8; i++) {
        if ((b & 1) !== 0) p ^= a;
        hiBitSet = (a & 0x80);
        a <<= 1;
        if (hiBitSet !== 0) a ^= 0x11b; /* x^8 + x^4 + x^3 + x + 1 */
        b >>= 1;
    }
    return p & 0xFF;
}

function stateToHexMatrix(state) {
    return state.map(row => row.map(v => v.toString(16).padStart(2,'0')));
}

function runAES128(textHex, keyHex, isEncrypt) {
    let stepsLog = "";
    
    // Parse hex to 1d array of bytes
    let tBytes = []; let kBytes = [];
    for(let i=0; i<32; i+=2) {
        tBytes.push(parseInt(textHex.substr(i, 2), 16));
        kBytes.push(parseInt(keyHex.substr(i, 2), 16));
    }
    
    // Key Expansion
    let w = []; // array of 4-byte words
    for(let i=0; i<4; i++) {
        w.push([kBytes[4*i], kBytes[4*i+1], kBytes[4*i+2], kBytes[4*i+3]]);
    }
    for(let i=4; i<44; i++) {
        let temp = [...w[i-1]];
        if (i%4 === 0) {
            // RotWord:
            let t = temp[0]; temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
            // SubWord:
            temp = temp.map(val => AES_SBOX[val]);
            // XOR Rcon:
            temp[0] ^= Rcon[i/4][0];
        }
        w.push([w[i-4][0]^temp[0], w[i-4][1]^temp[1], w[i-4][2]^temp[2], w[i-4][3]^temp[3]]);
    }
    
    // Convert text to state: 4x4 column-major
    let state = [];
    for(let r=0; r<4; r++) {
        state.push([tBytes[r], tBytes[r+4], tBytes[r+8], tBytes[r+12]]);
    }
    
    stepsLog += Utils.formatStep("Input State & Key Expansion Complete", `Initial State:\n${Utils.formatMatrix(stateToHexMatrix(state))}`);
    
    let addRoundKey = (state, round) => {
        for(let c=0; c<4; c++) {
            for(let r=0; r<4; r++) {
                state[r][c] ^= w[round*4 + c][r];
            }
        }
    };
    
    let subBytes = (state, inv=false) => {
        let box = inv ? AES_INV_SBOX : AES_SBOX;
        for(let r=0; r<4; r++) {
            for(let c=0; c<4; c++) {
                state[r][c] = box[state[r][c]];
            }
        }
    };
    
    let shiftRows = (state, inv=false) => {
        let temp = [[...state[0]], [...state[1]], [...state[2]], [...state[3]]];
        for(let r=1; r<4; r++) {
            for(let c=0; c<4; c++) {
                if(!inv) state[r][c] = temp[r][(c+r)%4];
                else state[r][c] = temp[r][(c-r+4)%4];
            }
        }
    };
    
    let mixColumns = (state, inv=false) => {
        let temp = [[...state[0]], [...state[1]], [...state[2]], [...state[3]]];
        for(let c=0; c<4; c++) {
            if(!inv) {
                state[0][c] = gfMul(0x02, temp[0][c]) ^ gfMul(0x03, temp[1][c]) ^ temp[2][c] ^ temp[3][c];
                state[1][c] = temp[0][c] ^ gfMul(0x02, temp[1][c]) ^ gfMul(0x03, temp[2][c]) ^ temp[3][c];
                state[2][c] = temp[0][c] ^ temp[1][c] ^ gfMul(0x02, temp[2][c]) ^ gfMul(0x03, temp[3][c]);
                state[3][c] = gfMul(0x03, temp[0][c]) ^ temp[1][c] ^ temp[2][c] ^ gfMul(0x02, temp[3][c]);
            } else {
                state[0][c] = gfMul(0x0e, temp[0][c]) ^ gfMul(0x0b, temp[1][c]) ^ gfMul(0x0d, temp[2][c]) ^ gfMul(0x09, temp[3][c]);
                state[1][c] = gfMul(0x09, temp[0][c]) ^ gfMul(0x0e, temp[1][c]) ^ gfMul(0x0b, temp[2][c]) ^ gfMul(0x0d, temp[3][c]);
                state[2][c] = gfMul(0x0d, temp[0][c]) ^ gfMul(0x09, temp[1][c]) ^ gfMul(0x0e, temp[2][c]) ^ gfMul(0x0b, temp[3][c]);
                state[3][c] = gfMul(0x0b, temp[0][c]) ^ gfMul(0x0d, temp[1][c]) ^ gfMul(0x09, temp[2][c]) ^ gfMul(0x0e, temp[3][c]);
            }
        }
    };
    
    if (isEncrypt) {
        addRoundKey(state, 0);
        stepsLog += Utils.formatStep(`Round 0 (Initial AddRoundKey)`, Utils.formatMatrix(stateToHexMatrix(state)));
        
        for(let i=1; i<=10; i++) {
            subBytes(state, false);
            shiftRows(state, false);
            if (i !== 10) mixColumns(state, false);
            addRoundKey(state, i);
            
            stepsLog += Utils.formatStep(`Round ${i}`, `SubBytes -> ShiftRows -> ${i!==10?"MixColumns -> ":""}AddRoundKey:\n${Utils.formatMatrix(stateToHexMatrix(state))}`);
        }
    } else {
        addRoundKey(state, 10);
        stepsLog += Utils.formatStep(`Round 10 (Initial AddRoundKey)`, Utils.formatMatrix(stateToHexMatrix(state)));
        
        for(let i=9; i>=0; i--) {
            shiftRows(state, true);
            subBytes(state, true);
            addRoundKey(state, i);
            if (i !== 0) mixColumns(state, true);
            
            stepsLog += Utils.formatStep(`Round ${i}`, `InvShiftRows -> InvSubBytes -> AddRoundKey${i!==0?" -> InvMixColumns":""}:\n${Utils.formatMatrix(stateToHexMatrix(state))}`);
        }
    }
    
    // state -> output
    let out = "";
    for(let c=0; c<4; c++) {
        for(let r=0; r<4; r++) {
            out += state[r][c].toString(16).padStart(2, '0').toUpperCase();
        }
    }
    
    return { result: out, steps: stepsLog };
}

registerCipher({
    id: "aes",
    name: "23. AES-128 (Advanced Encryption Standard)",
    category: "Symmetric Standards",
    description: "128-bit block, 10 rounds of substitution-permutation logic over GF(2^8).",
    inputs: [
        { id: "text", type: "text", label: "Data Block (32 Hex Digits)", placeholder: "00112233445566778899AABBCCDDEEFF" },
        { id: "key", type: "text", label: "Key (32 Hex Digits)", placeholder: "000102030405060708090A0B0C0D0E0F" }
    ],
    encrypt: (inputs) => runAES128(inputs.text.padEnd(32, '0').slice(0, 32), inputs.key.padEnd(32, '0').slice(0, 32), true),
    decrypt: (inputs) => runAES128(inputs.text.padEnd(32, '0').slice(0, 32), inputs.key.padEnd(32, '0').slice(0, 32), false)
});
