// app.js - UI Controller

document.addEventListener('DOMContentLoaded', () => {
    const sidebar = document.getElementById('sidebar');
    const navMenu = document.getElementById('nav-menu');
    const mobileMenuBtn = document.getElementById('mobile-menu-btn');
    const welcomeView = document.getElementById('welcome-view');
    const cipherView = document.getElementById('cipher-view');
    
    const cipherTitle = document.getElementById('cipher-title');
    const cipherDesc = document.getElementById('cipher-description');
    const cipherInputs = document.getElementById('cipher-inputs');
    const btnEncrypt = document.getElementById('btn-encrypt');
    const btnDecrypt = document.getElementById('btn-decrypt');
    
    const cipherOutput = document.getElementById('cipher-output');
    const outputText = document.getElementById('output-text');
    const btnCopy = document.getElementById('btn-copy');
    const btnToggleSteps = document.getElementById('btn-toggle-steps');
    const stepsContent = document.getElementById('steps-content');
    
    let currentCipher = null;

    // Mobile menu toggle
    mobileMenuBtn.addEventListener('click', () => {
        sidebar.classList.toggle('show');
    });

    // Populate Sidebar
    CipherRegistry.categories.forEach(category => {
        const catCiphers = CipherRegistry.list.filter(c => c.category === category);
        if (catCiphers.length > 0) {
            const catTitle = document.createElement('div');
            catTitle.className = 'category-title';
            catTitle.textContent = category;
            navMenu.appendChild(catTitle);

            catCiphers.forEach(cipher => {
                const item = document.createElement('div');
                item.className = 'nav-item';
                item.textContent = cipher.name;
                item.addEventListener('click', () => {
                    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
                    item.classList.add('active');
                    if (window.innerWidth <= 768) {
                        sidebar.classList.remove('show');
                    }
                    loadCipher(cipher);
                });
                navMenu.appendChild(item);
            });
        }
    });

    function loadCipher(cipher) {
        currentCipher = cipher;
        welcomeView.classList.add('hidden');
        cipherView.classList.remove('hidden');
        cipherOutput.classList.add('hidden');
        
        cipherTitle.textContent = cipher.name;
        cipherDesc.textContent = cipher.description;
        
        // Render inputs
        cipherInputs.innerHTML = '';
        cipher.inputs.forEach(inputDef => {
            const group = document.createElement('div');
            group.className = 'input-group';
            
            const label = document.createElement('label');
            label.textContent = inputDef.label;
            label.setAttribute('for', 'input-' + inputDef.id);
            group.appendChild(label);
            
            let inputEl;
            if (inputDef.type === 'textarea') {
                inputEl = document.createElement('textarea');
                inputEl.placeholder = 'Enter text here...';
            } else {
                inputEl = document.createElement('input');
                inputEl.type = inputDef.type === 'number' ? 'number' : 'text';
                inputEl.placeholder = inputDef.placeholder || '';
            }
            inputEl.id = 'input-' + inputDef.id;
            
            group.appendChild(inputEl);
            
            const errorEl = document.createElement('div');
            errorEl.className = 'error-msg';
            errorEl.id = 'error-' + inputDef.id;
            group.appendChild(errorEl);
            
            cipherInputs.appendChild(group);
        });
        
        btnEncrypt.onclick = () => executeCipher('encrypt');
        btnDecrypt.onclick = () => executeCipher('decrypt');
    }

    function getInputs() {
        const values = {};
        let hasError = false;
        
        document.querySelectorAll('.error-msg').forEach(el => {
            el.style.display = 'none';
            el.textContent = '';
        });

        currentCipher.inputs.forEach(inputDef => {
            const el = document.getElementById('input-' + inputDef.id);
            const val = el.value.trim();
            if (!val && inputDef.id !== 'text') {
                const err = document.getElementById('error-' + inputDef.id);
                err.textContent = 'This field is required.';
                err.style.display = 'block';
                hasError = true;
            }
            // Additional basic validations can go here or be delegated to the cipher
            if (inputDef.type === 'number') {
                values[inputDef.id] = parseFloat(val);
                if (isNaN(values[inputDef.id])) {
                    const err = document.getElementById('error-' + inputDef.id);
                    err.textContent = 'Must be a valid number.';
                    err.style.display = 'block';
                    hasError = true;
                }
            } else {
                values[inputDef.id] = val;
            }
        });
        
        return hasError ? null : values;
    }

    function executeCipher(mode) {
        if (!currentCipher) return;
        const inputs = getInputs();
        if (!inputs) return; // Validation failed
        
        try {
            let res;
            if (mode === 'encrypt') {
                res = currentCipher.encrypt(inputs);
            } else {
                res = currentCipher.decrypt(inputs);
            }
            
            outputText.textContent = res.result;
            stepsContent.innerHTML = res.steps;
            stepsContent.classList.remove('active');
            cipherOutput.classList.remove('hidden');
            
            // Render frequency chart if decrypting or encrypting textual data
            if (currentCipher.category === "Classical Ciphers" || currentCipher.category === "Transposition Ciphers") {
                Utils.renderFrequencyChart(res.result, 'freq-analysis-container');
            } else {
                document.getElementById('freq-analysis-container').classList.add('hidden');
            }

        } catch (e) {
            outputText.textContent = "ERROR: " + e.message;
            stepsContent.innerHTML = "<div class='error-msg' style='display:block'>" + e.stack + "</div>";
            cipherOutput.classList.remove('hidden');
            document.getElementById('freq-analysis-container').classList.add('hidden');
        }
    }

    btnToggleSteps.addEventListener('click', () => {
        stepsContent.classList.toggle('active');
        const arrow = btnToggleSteps.querySelector('.arrow');
        if (stepsContent.classList.contains('active')) {
            arrow.textContent = '▲';
        } else {
            arrow.textContent = '▼';
        }
    });

    btnCopy.addEventListener('click', () => {
        navigator.clipboard.writeText(outputText.textContent).then(() => {
            const temp = btnCopy.textContent;
            btnCopy.textContent = 'COPIED!';
            setTimeout(() => { btnCopy.textContent = temp; }, 2000);
        });
    });
});
