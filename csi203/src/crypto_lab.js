class CryptoSimulation {
    constructor() {
        this.statusLog = document.getElementById('status-log');
        this.bobRsaKeys = null;
        this.sharedSessionKey = null; // This will be the AES key
        this.aesKeyRaw = null;
        this.ciphertext = null;
        this.iv = window.crypto.getRandomValues(new Uint8Array(12)); // IV for AES-GCM

        this.initEventListeners();
    }

    log(message, type = 'system') {
        const entry = document.createElement('div');
        entry.className = `log-entry ${type}`;
        const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        entry.innerHTML = `<span style="opacity: 0.5">[${time}]</span> ${message}`;
        this.statusLog.prepend(entry);
    }

    initEventListeners() {
        document.getElementById('btn-gen-rsa').addEventListener('click', () => this.generateBobRSA());
        document.getElementById('btn-exchange-key').addEventListener('click', () => this.performKeyExchange());
        document.getElementById('btn-encrypt').addEventListener('click', () => this.encryptMessage());
        document.getElementById('btn-decrypt').addEventListener('click', () => this.decryptMessage());
    }

    /**
     * Step 1: Bob generates an RSA key pair
     */
    async generateBobRSA() {
        try {
            this.log("Bob is generating RSA 1024-bit key pair...", "bob");
            
            // Forge generates RSA key pair
            const pki = forge.pki;
            const keypair = pki.rsa.generateKeyPair({bits: 1024, e: 0x10001});
            this.bobRsaKeys = keypair;

            const pkPem = pki.publicKeyToPem(keypair.publicKey);
            
            // Show Bob's status
            document.getElementById('rsa-status').innerHTML = `<i class="fas fa-circle-check" style="color: #22c55e"></i> Key Pair Ready`;
            
            // Simulate sending Public Key to Alice
            this.log("Bob shared his Public Key with Alice.", "success");
            
            const pkString = pkPem.replace('-----BEGIN PUBLIC KEY-----', '').substring(0, 32) + "...";
            document.getElementById('alice-public-key-bob').innerText = pkString;
            
            this.log("Alice received Bob's Public Key.", "alice");
        } catch (e) {
            this.log("Error generating RSA keys: " + e.message, "error");
        }
    }

    /**
     * Step 2: Alice generates an AES key and sends it to Bob (Encrypted with RSA)
     */
    async performKeyExchange() {
        if (!this.bobRsaKeys) {
            this.log("Error: Alice needs Bob's Public Key first!", "error");
            return;
        }

        try {
            this.log("Alice is generating a random AES-128 Session Key...", "alice");
            
            // 1. Alice generates AES Key (16 bytes = 128 bit)
            this.aesKeyRaw = forge.random.getBytesSync(16);
            
            this.log("Alice is encrypting the AES key with Bob's RSA Public Key...", "alice");

            // 2. Alice encrypts AES Key with Bob's Public RSA Key using RSA-OAEP
            const encryptedAesKey = this.bobRsaKeys.publicKey.encrypt(this.aesKeyRaw, 'RSA-OAEP');

            // 3. Animation: Send encrypted key to Bob
            await this.animatePacket("forward", "Encrypted Session Key (RSA-OAEP)");

            this.log("Bob received the encrypted packet.", "bob");
            this.log("Bob is decrypting the session key using his PRIVATE Key...", "bob");

            // 4. Bob decrypts the AES key using his Private RSA Key
            const decryptedAesRaw = this.bobRsaKeys.privateKey.decrypt(encryptedAesKey, 'RSA-OAEP');

            this.sharedSessionKey = decryptedAesRaw; // success

            this.log("Success! Both Alice and Bob now share the same AES key.", "success");
            
            const hexKey = forge.util.bytesToHex(this.sharedSessionKey);
            document.getElementById('bob-session-key').innerText = hexKey.substring(0, 16) + "...";
            document.getElementById('btn-encrypt').classList.remove('disabled');
            document.getElementById('btn-encrypt').removeAttribute('disabled');
            
        } catch (e) {
            this.log("Key Exchange failed: " + e.message, "error");
            console.error(e);
        }
    }

    /**
     * Step 3: Alice encrypts her message with AES
     */
    async encryptMessage() {
        const text = document.getElementById('plain-text').value;
        if (!text) return;

        try {
            this.log("Alice is encrypting the message with AES-GCM...", "alice");
            
            this.iv = forge.random.getBytesSync(12);
            const cipher = forge.cipher.createCipher('AES-GCM', this.sharedSessionKey);
            cipher.start({ iv: this.iv });
            cipher.update(forge.util.createBuffer(text, 'utf8'));
            cipher.finish();

            this.ciphertext = cipher.output.getBytes();
            this.tag = cipher.mode.tag.getBytes();

            const hexCipher = forge.util.bytesToHex(this.ciphertext);
            
            this.log("Message encrypted. Sending to Bob...", "alice");
            
            await this.animatePacket("forward", "Encrypted Message (AES)");

            document.getElementById('bob-received-cipher').innerText = hexCipher.substring(0, 64) + "...";
            document.getElementById('btn-decrypt').classList.remove('disabled');
            document.getElementById('btn-decrypt').removeAttribute('disabled');
            
            this.log("Bob received the ciphertext.", "bob");
        } catch (e) {
            this.log("Encryption failed: " + e.message, "error");
        }
    }

    /**
     * Step 4: Bob decrypts the message
     */
    async decryptMessage() {
        try {
            this.log("Bob is decrypting the message using the shared AES key...", "bob");
            
            const decipher = forge.cipher.createDecipher('AES-GCM', this.sharedSessionKey);
            decipher.start({
                iv: this.iv,
                tag: forge.util.createBuffer(this.tag)
            });
            decipher.update(forge.util.createBuffer(this.ciphertext));
            const pass = decipher.finish();

            if (!pass) throw new Error("Decryption validation failed (Tag mismatch)");

            const decoded = decipher.output.toString('utf8');
            
            this.log("Decryption successful!", "success");
            
            const resultDiv = document.getElementById('decrypted-result');
            resultDiv.classList.remove('hidden');
            document.getElementById('decrypted-text').innerText = decoded;
            
        } catch (e) {
            this.log("Decryption failed! Potential key mismatch.", "error");
        }
    }

    /**
     * UI Helper: Animate the data packet
     */
    animatePacket(direction, label) {
        return new Promise((resolve) => {
            const packet = document.getElementById('data-packet');
            packet.classList.remove('hidden', 'anim-forward', 'anim-backward');
            
            // Force reflow
            void packet.offsetWidth;
            
            packet.classList.add(direction === "forward" ? 'anim-forward' : 'anim-backward');
            this.log(`Transmission: ${label}`, "system");
            
            // Removed socket.emit to prevent fake packets on live dashboard

            setTimeout(() => {
                packet.classList.add('hidden');
                resolve();
            }, 1000);
        });
    }

    buf2hex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
}

// Initialize on load
window.addEventListener('load', () => {
    new CryptoSimulation();
});
