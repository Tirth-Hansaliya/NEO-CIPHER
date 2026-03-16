<logo or banner goes here>

# NEO-CIPHER 🔐

A comprehensive, futuristic **Cryptography & Cipher Calculator** with support for classical, modern, and asymmetric encryption algorithms. Built as a standalone HTML web application with a sleek, interactive dark theme.

## 🚀 Features

* **Advanced Cipher Library**: Supports 23 different cryptographic algorithms.
* **Classical Algorithms**: Caesar, Vigenère, Playfair, Hill, Affine, Rail Fence, and more.
* **Modern Encryption**: DES, AES, Feistel network simulations.
* **Asymmetric Cryptography**: RSA, Rabin, ElGamal, and Diffie-Hellman Key Exchange.
* **Step-by-Step Explanations**: Academic-style algorithmic breakdowns and step-by-step mathematical reasoning for generated outputs.
* **Frequency Analysis**: Built-in visual frequency analysis chart for ciphertext evaluation.
* **Premium UI/UX**: Futuristic hacker/cyberpunk dark mode design with micro-animations and responsive layout.
* **Zero Dependencies**: Entirely frontend. Runs entirely locally in browser via HTML/CSS/JS without needing a server.
* **Matrix / Mathematics Tools**: Includes background helpers for modular arithmetic, matrix multiplication, and Euler's Totient calculations.

## 💻 Tech Stack

- **HTML5** Structure
- **CSS3** Styling (Custom properties, grid, flexbox, animations)
- **Vanilla JavaScript (ES6+)** for all logic, mathematics, and UI state management. No external libraries or frameworks used.

## 🛠️ Installation & Usage

Since the project is a standalone web wrapper:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Tirth-Hansaliya/NEO-CIPHER.git
   ```
   *(Or download the `.zip` file and extract it.)*

2. **Open the Application:**
   Navigate into the downloaded folder and open `cipher-calculator.html` in any modern web browser (Chrome, Firefox, Edge, Safari).
   
   *Alternatively, if you use VS Code, use the "Live Server" extension for a better development experience.*

## 📂 Project Structure

```text
NEO-CIPHER/
├── cipher-calculator.html    # The main entry webpage (Bundled UI)
├── README.md                 # Project Documentation
└── cipher_project/           # Source files (if you prefer modular development)
    ├── src/
        ├── css/
        │   └── styles.css
        ├── js/
            ├── app.js
            ├── utils.js
            ├── ciphers_classical.js
            ├── ciphers_modern.js
            └── ciphers_asymmetric.js
```

> **Note:** The `cipher-calculator.html` file serves as a compiled, single-file version of the source modules found in `cipher_project` for easy distribution.

## 🛡️ License

This project is licensed under the MIT License - feel free to build upon it, learn from the math functions, and use it in your own projects!