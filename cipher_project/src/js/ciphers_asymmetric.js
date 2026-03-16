// ciphers_asymmetric.js - Algorithms 18 to 21

// 18. RSA
registerCipher({
    id: "rsa",
    name: "18. RSA (Rivest-Shamir-Adleman)",
    category: "Asymmetric Ciphers",
    description: "Public key encryption and decryption. M < N. (Leave p,q blank to auto-generate).",
    inputs: [
        { id: "text", type: "number", label: "Message / Ciphertext as an Integer (e.g. 8)" },
        { id: "p", type: "text", label: "Prime p (leave blank for random)" },
        { id: "q", type: "text", label: "Prime q (leave blank for random)" },
        { id: "e", type: "text", label: "Public Exponent e (leave blank for default)" }
    ],
    encrypt: (inputs) => {
        let m = BigInt(inputs.text);
        
        let pStr = inputs.p.trim();
        let qStr = inputs.q.trim();
        let eStr = inputs.e.trim();
        
        // --- Input parsing ---
        let p, q;
        if (!pStr || !qStr) {
            let primes = Utils.generatePrimePair(10, 100);
            p = BigInt(primes[0]);
            q = BigInt(primes[1]);
        } else {
            p = BigInt(pStr);
            q = BigInt(qStr);
        }
        
        let n = p * q;
        let phi = (p - 1n) * (q - 1n);
        
        // Find e
        let e;
        if (eStr) {
            e = BigInt(eStr);
        } else {
            e = 3n;
            while(Utils.gcd(Number(e), Number(phi)) !== 1 && e < phi) e += 2n;
        }
        
        // Find d
        let d = BigInt(Utils.modInverse(Number(e), Number(phi)));
        
        let c = Utils.modExp(m, e, n);
        
        // --- Build Academic Formatting ---
        let steps = Utils.formatStep("Given Parameters", `Message (M = ${m})\nPrime (p = ${p})\nPrime (q = ${q})\nPublic exponent (e = ${e})`);
        
        steps += Utils.formatStep("Step 1: Compute (n)", `n = p × q\nn = ${p} × ${q} = ${n}`);
        
        steps += Utils.formatStep("Step 2: Compute Euler's Totient φ(n)", `φ(n) = (p-1)(q-1)\nφ(n) = (${p}-1)(${q}-1)\nφ(n) = ${p-1n} × ${q-1n} = ${phi}`);
        
        steps += Utils.formatStep("Step 3: Public Key", `Public key = (e, n)\n(e, n) = (${e}, ${n})`);
        
        steps += Utils.formatStep("Step 4: Find Private Key (d)", `We need:\nd × e ≡ 1 (mod φ(n))\nd × ${e} ≡ 1 (mod ${phi})\n\nFind (d):\n${e} × ${d} = ${e*d}\n${e*d} mod ${phi} = 1\n\nSo\nd = ${d}\n\nPrivate key:\n(d, n) = (${d}, ${n})`);
        
        steps += Utils.formatStep("Step 5: Encryption", `Formula:\nC = M^e mod n\nC = ${m}^${e} mod ${n}\n\nCalculate:\n${m}^${e} = ${m**e}\n${m**e} mod ${n} = ${c}\n\nCiphertext:\nC = ${c}`);
        
        // Add a nice table sum-up
        let sumTable = `| Item        | Value     |\n| ----------- | --------- |\n| p           | ${p}        |\n| q           | ${q}        |\n| n           | ${n}       |\n| φ(n)        | ${phi}       |\n| Public key  | (${e}, ${n})  |\n| Private key | (${d}, ${n}) |\n| Ciphertext  | ${c}        |`.replace(/\|/g, '<span style="color:var(--text-dim)">|</span>');
        
        steps += Utils.formatStep("Final Results Table", sumTable + `\n\n✅ Encrypted message = ${c}`);
        
        return { result: c.toString(), steps: steps };
    },
    decrypt: (inputs) => {
        let c = BigInt(inputs.text);
        
        let pStr = inputs.p.trim();
        let qStr = inputs.q.trim();
        let eStr = inputs.e.trim();
        if (!pStr || !qStr || !eStr) throw new Error("Requires p, q, and e for decryption.");
        
        let p = BigInt(pStr);
        let q = BigInt(qStr);
        let n = p * q;
        let phi = (p - 1n) * (q - 1n);
        let e = BigInt(eStr);
        let d = BigInt(Utils.modInverse(Number(e), Number(phi)));
        
        let m = Utils.modExp(c, d, n);
        
        let steps = Utils.formatStep("Given Parameters", `Ciphertext (C = ${c})\nPrime (p = ${p})\nPrime (q = ${q})\nPublic exponent (e = ${e})`);
        
        steps += Utils.formatStep("Step 1: Compute n and φ(n)", `n = ${p} × ${q} = ${n}\nφ(n) = ${p-1n} × ${q-1n} = ${phi}`);
        
        steps += Utils.formatStep("Step 2: Find Private Key (d)", `d × ${e} ≡ 1 (mod ${phi})\nd = ${d}`);
        
        steps += Utils.formatStep("Step 3: Decryption (Verification)", `Formula:\nM = C^d mod n\nM = ${c}^${d} mod ${n}\n\nResult:\nM = ${m}\n\nOriginal message recovered ✅`);
        
        return { result: m.toString(), steps: steps };
    }
});

// 19. Rabin Cipher with CRT
registerCipher({
    id: "rabin",
    name: "19. Rabin Cipher (CRT)",
    category: "Asymmetric Ciphers",
    description: "C = M^2 mod N. Decryption uses Chinese Remainder Theorem to find 4 roots. M < N. p and q must be ≡ 3 mod 4.",
    inputs: [
        { id: "text", type: "number", label: "Message / Ciphertext Integer" },
        { id: "p", type: "text", label: "Prime p ≡ 3 mod 4 (blank for random)" },
        { id: "q", type: "text", label: "Prime q ≡ 3 mod 4 (blank for random)" }
    ],
    encrypt: (inputs) => {
        let m = BigInt(inputs.text);
        
        let p, q;
        if (!inputs.p || !inputs.q) {
            p = 7n; q = 11n; // defaults
            while (true) {
                let pair = Utils.generatePrimePair(10, 100);
                if (pair[0] % 4 === 3 && pair[1] % 4 === 3) {
                    p = BigInt(pair[0]); q = BigInt(pair[1]); break;
                }
            }
        } else {
            p = BigInt(inputs.p); q = BigInt(inputs.q);
        }
        
        let n = p * q;
        let c = Utils.modExp(m, 2n, n);
        
        let steps = Utils.formatStep("Keys", `p = ${p}\nq = ${q}\nn = p * q = ${n}\nPublic Key: ${n}`);
        steps += Utils.formatStep("Encryption", `M = ${m}\nC = M^2 mod n = ${m}^2 mod ${n} = ${c}`);
        return { result: c.toString(), steps: steps + Utils.formatStep("Result", c.toString()) };
    },
    decrypt: (inputs) => {
        let c = BigInt(inputs.text);
        let p = BigInt(inputs.p); let q = BigInt(inputs.q);
        if (!p || !q) throw new Error("Requires p and q for decryption.");
        
        let n = p * q;
        
        // Find roots m_p, m_q
        let mp = Utils.modExp(c, (p + 1n) / 4n, p);
        let mq = Utils.modExp(c, (q + 1n) / 4n, q);
        
        // Extended Euclidean
        let e = Utils.gcdExt(Number(p), Number(q));
        let yp = BigInt(e.x); // coeff for p
        let yq = BigInt(e.y); // coeff for q
        
        // CRT
        let r1 = ((yp * p * mq) + (yq * q * mp)) % n; r1 = (r1 + n) % n;
        let r2 = n - r1;
        let r3 = ((yp * p * mq) - (yq * q * mp)) % n; r3 = (r3 + n) % n;
        let r4 = n - r3;
        
        let steps = Utils.formatStep("Roots in Subgroups", `mp = C^((p+1)/4) mod p = ${mp}\nmq = C^((q+1)/4) mod q = ${mq}`);
        steps += Utils.formatStep("Extended Euclidean Algorithm", `yp = ${yp}, yq = ${yq} such that yp*p + yq*q = 1`);
        steps += Utils.formatStep("Chinese Remainder Theorem", `r1 = (yp*p*mq + yq*q*mp) mod n = ${r1}\nr2 = n - r1 = ${r2}\nr3 = (yp*p*mq - yq*q*mp) mod n = ${r3}\nr4 = n - r3 = ${r4}`);
        
        let roots = [...new Set([r1,r2,r3,r4].map(x => x.toString()))].sort();
        return { result: roots.join(', '), steps: steps + Utils.formatStep("4 Possible Roots", roots.join(', ')) };
    }
});

// 20. ElGamal
registerCipher({
    id: "elgamal",
    name: "20. ElGamal Encryption",
    category: "Asymmetric Ciphers",
    description: "Public key system using discrete logarithms.",
    inputs: [
        { id: "text", type: "text", label: "Msg Integer (Enc) OR C1,C2 (Dec, comma separated)" },
        { id: "p", type: "number", label: "Prime p" },
        { id: "g", type: "number", label: "Generator g" },
        { id: "x", type: "number", label: "Private Key x (or Public Key y for Encrypt)" },
        { id: "k", type: "text", label: "Random k (for Encrypt only, blank for random)" }
    ],
    encrypt: (inputs) => {
        let m = BigInt(inputs.text);
        let p = BigInt(inputs.p);
        let g = BigInt(inputs.g);
        let y = BigInt(inputs.x); // Provided as y in encrypt
        
        let k;
        if (inputs.k) {
            k = BigInt(inputs.k);
        } else {
            k = BigInt(Math.floor(Math.random() * Number(p-2n)) + 1);
        }
        
        let c1 = Utils.modExp(g, k, p);
        let s = Utils.modExp(y, k, p);
        let c2 = (m * s) % p;
        
        let steps = Utils.formatStep("Keys & Parameters", `p = ${p}, g = ${g}, y (public) = ${y}\nk (random) = ${k}`);
        steps += Utils.formatStep("Encryption Computations", `C1 = g^k mod p = ${g}^${k} mod ${p} = ${c1}\nShared s = y^k mod p = ${s}\nC2 = (M * s) mod p = (${m} * ${s}) mod ${p} = ${c2}`);
        
        return { result: `${c1}, ${c2}`, steps: steps + Utils.formatStep("Ciphertext Pair (C1, C2)", `${c1}, ${c2}`) };
    },
    decrypt: (inputs) => {
        let parts = inputs.text.split(',').map(n => n.trim());
        if (parts.length !== 2) throw new Error("Ciphertext must be C1, C2 separated by comma.");
        let c1 = BigInt(parts[0]);
        let c2 = BigInt(parts[1]);
        
        let p = BigInt(inputs.p);
        let g = BigInt(inputs.g); // Not strictly needed for dec, but good to have
        let x = BigInt(inputs.x); // Private key
        
        let s = Utils.modExp(c1, x, p);
        let sInv = BigInt(Utils.modInverse(Number(s), Number(p)));
        let m = (c2 * sInv) % p;
        
        let steps = Utils.formatStep("Keys & Parameters", `p = ${p}, x (private) = ${x}\nCiphertext (C1, C2) = (${c1}, ${c2})`);
        steps += Utils.formatStep("Decryption Computations", `Shared s = C1^x mod p = ${c1}^${x} mod ${p} = ${s}\ns^-1 mod p = ${sInv}\nM = (C2 * s^-1) mod p = (${c2} * ${sInv}) mod ${p} = ${m}`);
        
        return { result: m.toString(), steps: steps + Utils.formatStep("Result", m.toString()) };
    }
});

// 21. Diffie-Hellman Key Exchange
registerCipher({
    id: "dh",
    name: "21. Diffie-Hellman Key Exchange",
    category: "Asymmetric Ciphers",
    description: "Computes shared secret K = (g^a)^b = (g^b)^a. Uses Encrypt for Alice, Decrypt for Bob.",
    inputs: [
        { id: "p", type: "number", label: "Prime p" },
        { id: "g", type: "number", label: "Generator g" },
        { id: "a", type: "number", label: "Alice's Secret (a)" },
        { id: "b", type: "number", label: "Bob's Secret (b)" }
    ],
    encrypt: (inputs) => { // Alice's Side
        let p = BigInt(inputs.p); let g = BigInt(inputs.g);
        let a = BigInt(inputs.a); let b = BigInt(inputs.b);
        
        let A = Utils.modExp(g, a, p); // Alice computes
        let B = Utils.modExp(g, b, p); // Bob computes
        let K = Utils.modExp(B, a, p); // Alice computes shared
        
        let steps = Utils.formatStep("Alice Computes Public A", `A = g^a mod p = ${g}^${a} mod ${p} = ${A}`);
        steps += Utils.formatStep("Bob Computes Public B", `B = g^b mod p = ${g}^${b} mod ${p} = ${B}`);
        steps += Utils.formatStep("Alice Computes Shared Secret", `K = B^a mod p = ${B}^${a} mod ${p} = ${K}`);
        
        return { result: K.toString(), steps };
    },
    decrypt: (inputs) => { // Bob's Side
        let p = BigInt(inputs.p); let g = BigInt(inputs.g);
        let a = BigInt(inputs.a); let b = BigInt(inputs.b);
        
        let A = Utils.modExp(g, a, p);
        let B = Utils.modExp(g, b, p);
        let K = Utils.modExp(A, b, p); // Bob computes shared
        
        let steps = Utils.formatStep("Bob Computes Public B", `B = g^b mod p = ${g}^${b} mod ${p} = ${B}`);
        steps += Utils.formatStep("Alice Computes Public A", `A = g^a mod p = ${g}^${a} mod ${p} = ${A}`);
        steps += Utils.formatStep("Bob Computes Shared Secret", `K = A^b mod p = ${A}^${b} mod ${p} = ${K}`);
        
        return { result: K.toString(), steps };
    }
});
