const crypto = require('crypto');
const fs = require('fs');

class PasswordManager {
    constructor(file = 'passwords.json', masterPasswordFile = 'master-password.json') {
        this.file = file;
        this.masterPasswordFile = masterPasswordFile;
        this.passwords = {};
        this.masterPasswordHash = null;
        this.key = null;
        this.hmacKey = null;

        // Check if master password already exists
        if (fs.existsSync(this.masterPasswordFile)) {
            this.loadMasterPassword(); // Load existing master password details
            this.loadPasswords();      // Load stored passwords if available
        }
    }

    // Loads the master password hash and salt if they exist
    loadMasterPassword() {
        const data = JSON.parse(fs.readFileSync(this.masterPasswordFile, 'utf8'));
        this.masterPasswordHash = data.masterPasswordHash;
        this.salt = Buffer.from(data.salt, 'hex');
    }

    // Derives encryption and HMAC keys from the master password using PBKDF2
    async deriveKeys(masterPassword, salt) {
        return new Promise((resolve, reject) => {
            crypto.pbkdf2(masterPassword, salt, 100000, 64, 'sha256', (err, derivedKey) => {
                if (err) return reject(err);
                this.key = derivedKey.slice(0, 32); // AES-256 key
                this.hmacKey = derivedKey.slice(32); // HMAC key
                resolve();
            });
        });
    }

    // Initializes the password manager with a new master password and salt
    async init(masterPassword) {
        this.salt = crypto.randomBytes(16); // Generate a new salt
        await this.deriveKeys(masterPassword, this.salt);
        this.masterPasswordHash = crypto.createHash('sha256').update(masterPassword).digest('hex');

        // Save master password hash and salt to file
        fs.writeFileSync(this.masterPasswordFile, JSON.stringify({
            masterPasswordHash: this.masterPasswordHash,
            salt: this.salt.toString('hex')
        }, null, 2), 'utf8');
    }

    // Loads the password manager by verifying the master password
    async load(masterPassword) {
        if (!this.masterPasswordHash || !this.salt) throw new Error("Master password not set.");

        const inputHash = crypto.createHash('sha256').update(masterPassword).digest('hex');
        if (inputHash !== this.masterPasswordHash) throw new Error("Incorrect master password.");
        await this.deriveKeys(masterPassword, this.salt);

        // Load stored passwords if available
        this.loadPasswords();
    }

    // Load passwords from file with integrity verification
    loadPasswords() {
        if (fs.existsSync(this.file)) {
            const data = JSON.parse(fs.readFileSync(this.file, 'utf8'));
            const { passwords, checksum } = data;
            const currentChecksum = crypto.createHash('sha256').update(JSON.stringify(passwords)).digest('hex');
            if (checksum !== currentChecksum) throw new Error("Data integrity check failed.");
            this.passwords = passwords;
        } else {
            this.passwords = {};
        }
    }

    // Encrypts data using AES-GCM
    encryptData(data) {
        const iv = crypto.randomBytes(12); // 96-bit IV
        const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const tag = cipher.getAuthTag();
        return { iv: iv.toString('hex'), encrypted, tag: tag.toString('hex') };
    }

    // Decrypts data using AES-GCM
    decryptData(encryptedData) {
        const { iv, encrypted, tag } = encryptedData;
        const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, Buffer.from(iv, 'hex'));
        decipher.setAuthTag(Buffer.from(tag, 'hex'));
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }

    // Hashes domain names using HMAC-SHA256
    hashDomain(domain) {
        return crypto.createHmac('sha256', this.hmacKey).update(domain).digest('hex');
    }

    // Save passwords and checksum to file
    savePasswords() {
        const checksum = crypto.createHash('sha256').update(JSON.stringify(this.passwords)).digest('hex');
        fs.writeFileSync(this.file, JSON.stringify({ passwords: this.passwords, checksum }, null, 2), 'utf8');
    }

    // Add a new password
    addPassword(service, password) {
        const hashedDomain = this.hashDomain(service);
        this.passwords[hashedDomain] = this.encryptData(password);
        this.savePasswords();
        
    }

    // Retrieve a password
    getPassword(service) {
        const hashedDomain = this.hashDomain(service);
        const encryptedPassword = this.passwords[hashedDomain];
        if (!encryptedPassword) throw new Error(`No password found for ${service}`);
        return this.decryptData(encryptedPassword);
    }

    // Delete a password
    deletePassword(service) {
        const hashedDomain = this.hashDomain(service);
        if (!this.passwords[hashedDomain]) throw new Error(`No password found for ${service}`);
        delete this.passwords[hashedDomain];
        this.savePasswords();
        
    }
}

module.exports = PasswordManager;
