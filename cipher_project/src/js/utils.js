// utils.js - General Helpers, Mathematical Functions, and UI Generators

const Utils = {
    // --- Math & Modular Arithmetic ---
    
    // Extended Euclidean Algorithm
    gcdExt(a, b) {
        if (a === 0) return { gcd: b, x: 0, y: 1 };
        const res = Utils.gcdExt(b % a, a);
        return {
            gcd: res.gcd,
            x: res.y - Math.floor(b / a) * res.x,
            y: res.x
        };
    },

    // Modular Inverse (returns x such that (a*x) % m == 1)
    modInverse(a, m) {
        // Ensure a is positive
        a = ((a % m) + m) % m;
        const res = Utils.gcdExt(a, m);
        if (res.gcd !== 1) {
            return null; // No inverse exists
        }
        return ((res.x % m) + m) % m;
    },

    // Greatest Common Divisor
    gcd(a, b) {
        while (b !== 0) {
            let temp = b;
            b = a % b;
            a = temp;
        }
        return Math.abs(a);
    },

    // Modular Exponentiation: (base^exp) % mod
    modExp(base, exp, mod) {
        if (mod === 1n) return 0n;
        let res = 1n;
        base = base % mod;
        while (exp > 0n) {
            if (exp % 2n === 1n) res = (res * base) % mod;
            exp = exp / 2n;
            base = (base * base) % mod;
        }
        return res;
    },

    // Mathematical Modulo (handles negative numbers)
    mod(n, m) {
        return ((n % m) + m) % m;
    },

    // Matrix Math for Hill Cipher
    matrixMultMod(mat1, mat2, m) {
        let res = Array(mat1.length).fill(0).map(() => Array(mat2[0].length).fill(0));
        for (let i = 0; i < mat1.length; i++) {
            for (let j = 0; j < mat2[0].length; j++) {
                let sum = 0;
                for (let k = 0; k < mat1[0].length; k++) {
                    sum += mat1[i][k] * mat2[k][j];
                }
                res[i][j] = Utils.mod(sum, m);
            }
        }
        return res;
    },

    determinant2x2(mat) {
        return mat[0][0] * mat[1][1] - mat[0][1] * mat[1][0];
    },

    inverse2x2Mod(mat, m) {
        let det = Utils.mod(Utils.determinant2x2(mat), m);
        let detInv = Utils.modInverse(det, m);
        if (detInv === null) return null;
        
        let inv = [
            [Utils.mod(mat[1][1] * detInv, m), Utils.mod(-mat[0][1] * detInv, m)],
            [Utils.mod(-mat[1][0] * detInv, m), Utils.mod(mat[0][0] * detInv, m)]
        ];
        return inv;
    },

    // --- String Helpers ---
    
    // Keep only alphabetic uppercase letters
    cleanAlpha(str) {
        return str.toUpperCase().replace(/[^A-Z]/g, '');
    },

    // Create chunks of size n
    chunkString(str, length) {
        return str.match(new RegExp('.{1,' + length + '}', 'g')) || [];
    },

    // --- Primes ---
    // Miller-Rabin Primality Test for small primes
    isPrime(n) {
        if (n <= 1) return false;
        if (n <= 3) return true;
        if (n % 2 === 0 || n % 3 === 0) return false;
        for (let i = 5; i * i <= n; i += 6) {
            if (n % i === 0 || n % (i + 2) === 0) return false;
        }
        return true;
    },

    // Find next prime > n
    nextPrime(n) {
        let p = n;
        while (!Utils.isPrime(p)) p++;
        return p;
    },

    // Small Primes Generator for Key Gen demonstration
    generatePrimePair(min=10, max=100) {
        let primes = [];
        for (let i = min; i <= max; i++) {
            if (Utils.isPrime(i)) primes.push(i);
        }
        let p1 = primes[Math.floor(Math.random() * primes.length)];
        let p2 = primes[Math.floor(Math.random() * primes.length)];
        while (p1 === p2) {
            p2 = primes[Math.floor(Math.random() * primes.length)];
        }
        return [p1, p2];
    },

    // --- UI/HTML Helpers ---
    formatStep(title, content) {
        return `
        <div class="step-block">
            <div class="step-label">${title}</div>
            <div class="step-content" style="white-space:pre-wrap; font-family:var(--font-mono);">${content}</div>
        </div>`;
    },
    
    // Generates the HTML for the internal array representations (like DES tables)
    formatMatrix(matrix) {
        let html = '<table class="matrix">';
        matrix.forEach(row => {
            html += '<tr>' + row.map(cell => `<td>${cell}</td>`).join('') + '</tr>';
        });
        html += '</table>';
        return html;
    },
    
    // Renders the Frequency Analysis bar chart
    renderFrequencyChart(text, containerId) {
        const container = document.getElementById(containerId);
        const chart = document.getElementById('freq-chart');
        
        let cleaned = Utils.cleanAlpha(text);
        if (!cleaned) {
            container.classList.add('hidden');
            return;
        }

        let freqs = {};
        let maxFreq = 0;
        for (let i=0; i<26; i++) {
            freqs[String.fromCharCode(65+i)] = 0;
        }
        for (let char of cleaned) {
            freqs[char]++;
        }
        for (let char in freqs) {
            if (freqs[char] > maxFreq) maxFreq = freqs[char];
        }

        let html = '';
        for (let char in freqs) {
            let height = maxFreq === 0 ? 0 : (freqs[char] / maxFreq) * 100;
            html += `
            <div class="bar-wrapper">
                <div class="bar-val">${freqs[char]}</div>
                <div class="bar" style="height: ${Math.max(1, height)}%"></div>
                <div class="bar-label">${char}</div>
            </div>`;
        }
        chart.innerHTML = html;
        container.classList.remove('hidden');
    }
};
