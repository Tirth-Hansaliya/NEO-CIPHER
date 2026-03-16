// ciphers_transposition.js - Algorithms 14 and 15

// 14. Columnar Transposition
registerCipher({
    id: "columnar",
    name: "14. Columnar Transposition",
    category: "Transposition Ciphers",
    description: "Write text in rows, read text down columns according to keyword alphabetical order.",
    inputs: [
        { id: "text", type: "textarea", label: "Text" },
        { id: "key", type: "text", label: "Keyword" }
    ],
    encrypt: (inputs) => {
        let text = Utils.cleanAlpha(inputs.text);
        let key = Utils.cleanAlpha(inputs.key);
        if (!key) throw new Error("Key cannot be empty.");
        
        let cols = key.length;
        let rows = Math.ceil(text.length / cols);
        let paddedText = text.padEnd(rows * cols, 'X');
        
        // Build Grid
        let grid = [];
        let rIndex = 0;
        for (let i = 0; i < rows; i++) {
            grid.push(paddedText.substring(rIndex, rIndex + cols).split(''));
            rIndex += cols;
        }

        // Determine column order
        let order = key.split('').map((char, originalIndex) => ({ char, originalIndex }));
        order.sort((a,b) => a.char.localeCompare(b.char));

        let res = "";
        let steps = Utils.formatStep("Key Order", order.map((o, i) => `${o.char} (${o.originalIndex + 1})`).join(' '));
        steps += Utils.formatStep("Grid", Utils.formatMatrix(grid));
        
        for (let i = 0; i < cols; i++) {
            let srcCol = order[i].originalIndex;
            for (let r = 0; r < rows; r++) {
                res += grid[r][srcCol];
            }
        }
        
        return { result: res, steps: steps + Utils.formatStep("Reading Columns", "Read grid top to bottom based on alphabetical order of keyword.") };
    },
    decrypt: (inputs) => {
        let text = Utils.cleanAlpha(inputs.text);
        let key = Utils.cleanAlpha(inputs.key);
        if (!key) throw new Error("Key cannot be empty.");
        
        let cols = key.length;
        let rows = Math.ceil(text.length / cols);
        if (text.length % cols !== 0) throw new Error("Ciphertext length must be a multiple of keyword length.");
        
        let order = key.split('').map((char, originalIndex) => ({ char, originalIndex }));
        order.sort((a,b) => a.char.localeCompare(b.char));
        
        let grid = Array(rows).fill(0).map(() => Array(cols).fill(''));
        
        let textIndex = 0;
        for (let i = 0; i < cols; i++) {
            let targetCol = order[i].originalIndex;
            for (let r = 0; r < rows; r++) {
                grid[r][targetCol] = text[textIndex++];
            }
        }
        
        let res = "";
        for (let r = 0; r < rows; r++) {
            res += grid[r].join('');
        }
        
        let steps = Utils.formatStep("Key Order", order.map((o, i) => `${o.char} (${o.originalIndex + 1})`).join(' '));
        steps += Utils.formatStep("Reconstructed Grid", Utils.formatMatrix(grid));
        return { result: res, steps };
    }
});

// 15. Rail Fence Cipher
registerCipher({
    id: "railfence",
    name: "15. Rail Fence Cipher",
    category: "Transposition Ciphers",
    description: "Write text in a zigzag across rails, then read row by row.",
    inputs: [
        { id: "text", type: "textarea", label: "Text" },
        { id: "rails", type: "number", label: "Number of Rails (e.g. 3)" }
    ],
    encrypt: (inputs) => {
        let text = Utils.cleanAlpha(inputs.text);
        let rails = parseInt(inputs.rails);
        if (rails < 2) throw new Error("Need at least 2 rails.");
        
        let grid = Array(rails).fill(0).map(() => Array(text.length).fill('.'));
        
        let r = 0;
        let dir = 1;
        for (let c = 0; c < text.length; c++) {
            grid[r][c] = text[c];
            r += dir;
            if (r === rails - 1 || r === 0) dir *= -1;
        }
        
        let res = "";
        for(let r=0; r<rails; r++) {
            for(let c=0; c<text.length; c++) {
                if(grid[r][c] !== '.') res += grid[r][c];
            }
        }
        return { result: res, steps: Utils.formatStep("Zig-Zag Rails", Utils.formatMatrix(grid)) };
    },
    decrypt: (inputs) => {
        let text = Utils.cleanAlpha(inputs.text);
        let rails = parseInt(inputs.rails);
        if (rails < 2) throw new Error("Need at least 2 rails.");
        
        let grid = Array(rails).fill(0).map(() => Array(text.length).fill('.'));
        
        // Mark spots
        let r = 0; let dir = 1;
        for (let c = 0; c < text.length; c++) {
            grid[r][c] = '*';
            r += dir;
            if (r === rails - 1 || r === 0) dir *= -1;
        }
        
        // Fill spots
        let idx = 0;
        for (r = 0; r < rails; r++) {
            for (let c = 0; c < text.length; c++) {
                if (grid[r][c] === '*' && idx < text.length) {
                    grid[r][c] = text[idx++];
                }
            }
        }
        
        // Read zigzag
        let res = "";
        r = 0; dir = 1;
        for (let c = 0; c < text.length; c++) {
            res += grid[r][c];
            r += dir;
            if (r === rails - 1 || r === 0) dir *= -1;
        }
        
        return { result: res, steps: Utils.formatStep("Reconstructed Rails", Utils.formatMatrix(grid)) };
    }
});
