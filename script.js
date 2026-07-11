// Tab Switching
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.cipher-panel').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(btn.dataset.cipher).classList.add('active');
    });
});


// Utility Functions
// ==========================================
function cleanText(text) {
    return text.toUpperCase().replace(/[^A-Z]/g, '');
}

function mod(n, m) {
    return ((n % m) + m) % m;
}

function gcd(a, b) {
    return b === 0 ? a : gcd(b, a % b);
}

function modInverse(a, m) {
    a = mod(a, m);
    for (let x = 1; x < m; x++) {
        if ((a * x) % m === 1) return x;
    }
    return null;
}

function gcdBigInt(a, b) {
    a = a < 0n ? -a : a;
    b = b < 0n ? -b : b;
    while (b !== 0n) {
        const temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

function modInverseBigInt(a, m) {
    let m0 = m;
    let x0 = 0n;
    let x1 = 1n;
    if (m === 1n) return 0n;
    while (a > 1n) {
        const q = a / m;
        let t = m;
        m = a % m;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0n) x1 += m0;
    return x1;
}

function modPow(base, exponent, modulus) {
    base = base % modulus;
    let result = 1n;
    while (exponent > 0n) {
        if (exponent % 2n === 1n) result = (result * base) % modulus;
        exponent = exponent / 2n;
        base = (base * base) % modulus;
    }
    return result;
}

function bytesToHex(buffer) {
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

function hexStringToBytes(hex) {
    const normalized = hex.replace(/[^0-9A-Fa-f]/g, '');
    if (normalized.length % 2 !== 0) return null;
    const bytes = new Uint8Array(normalized.length / 2);
    for (let i = 0; i < normalized.length; i += 2) {
        bytes[i / 2] = parseInt(normalized.substr(i, 2), 16);
    }
    return bytes;
}

function normalizeAesKey(key) {
    const raw = new TextEncoder().encode(key);
    const size = 16;
    const result = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
        result[i] = raw[i] || 0;
    }
    return result;
}

function stringToBytes(str) {
    return new TextEncoder().encode(str);
}

function bytesToString(bytes) {
    return new TextDecoder().decode(bytes);
}

function pad8(input) {
    const bytes = typeof input === 'string' ? stringToBytes(input) : input;
    const result = new Uint8Array(Math.ceil(bytes.length / 8) * 8);
    result.set(bytes);
    return result;
}

function bytesToUint32(bytes, offset = 0) {
    return ((bytes[offset] << 24) >>> 0) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
}

function uint32ToBytes(value) {
    return new Uint8Array([
        (value >>> 24) & 0xff,
        (value >>> 16) & 0xff,
        (value >>> 8) & 0xff,
        value & 0xff,
    ]);
}

function rotateLeft32(value, shift) {
    return ((value << shift) | (value >>> (32 - shift))) >>> 0;
}

function desRoundKey(keyBytes, round) {
    let value = 0;
    for (let i = 0; i < 4; i++) {
        value = ((value << 8) | keyBytes[(round + i) % 8]) >>> 0;
    }
    return value ^ round;
}

function desFeistel(half, roundKey) {
    return rotateLeft32(half ^ roundKey, roundKey % 32);
}

function simpleDesBlock(blockBytes, keyBytes, reverse = false) {
    let left = bytesToUint32(blockBytes, 0);
    let right = bytesToUint32(blockBytes, 4);
    const rounds = [...Array(16).keys()];
    if (reverse) rounds.reverse();
    for (const round of rounds) {
        const roundKey = desRoundKey(keyBytes, round);
        const nextLeft = right;
        const nextRight = left ^ desFeistel(right, roundKey);
        left = nextLeft;
        right = nextRight;
    }
    const out = new Uint8Array(8);
    out.set(uint32ToBytes(left), 0);
    out.set(uint32ToBytes(right), 4);
    return out;
}

function encryptDesText(text, key) {
    const keyBytes = pad8(new TextEncoder().encode(key.padEnd(8, '\0'))).slice(0, 8);
    const padded = pad8(text);
    const result = new Uint8Array(padded.length);
    for (let i = 0; i < padded.length; i += 8) {
        result.set(simpleDesBlock(padded.slice(i, i + 8), keyBytes, false), i);
    }
    return arrayBufferToBase64(result.buffer);
}

function decryptDesText(cipher, key) {
    try {
        const keyBytes = pad8(new TextEncoder().encode(key.padEnd(8, '\0'))).slice(0, 8);
        const input = new Uint8Array(base64ToArrayBuffer(cipher));
        const result = new Uint8Array(input.length);
        for (let i = 0; i < input.length; i += 8) {
            result.set(simpleDesBlock(input.slice(i, i + 8), keyBytes, true), i);
        }
        return bytesToString(result).replace(/\0+$/, '');
    } catch (error) {
        return 'Error: Invalid DES ciphertext or key.';
    }
}

function setTextValue(id, value) {
    document.getElementById(id).value = value;
}


// Caesar Cipher
// ==========================================
function caesarEncrypt(text, shift) {
    shift = mod(shift, 26); 
    return text.split('').map(char => {
        if (char >= 'A' && char <= 'Z') {
            return String.fromCharCode(((char.charCodeAt(0) - 65 + shift) % 26) + 65);
        } else if (char >= 'a' && char <= 'z') { 
            return String.fromCharCode(((char.charCodeAt(0) - 97 + shift) % 26) + 97);
        }
        return char;
    }).join('');
}

function caesarDecrypt(text, shift) {
    return caesarEncrypt(text, 26 - mod(shift, 26)); 
}

function encryptCaesar() {
    const plain = document.getElementById('caesar-plain').value;
    const shift = parseInt(document.getElementById('caesar-shift').value) || 0;
    document.getElementById('caesar-cipher').value = caesarEncrypt(plain, shift);
}

function decryptCaesar() {
    const cipher = document.getElementById('caesar-cipher').value;
    const shift = parseInt(document.getElementById('caesar-shift').value) || 0;
    document.getElementById('caesar-plain').value = caesarDecrypt(cipher, shift);
}


// Vigenere Cipher
// ==========================================
function generateKey(msg, key) {
    msg = msg.toUpperCase();
    key = key.toUpperCase();

    while (key.length < msg.length) {
        key += key;
    }

    return key.slice(0, msg.length);
}

function encryptVigenereAlgo(msg, key) {
    msg = msg.toUpperCase();
    key = generateKey(cleanText(msg).length ? cleanText(msg) : msg, key); 

    let result = "";
    let keyIndex = 0;

    for (let i = 0; i < msg.length; i++) {
        const char = msg[i];
        if (char >= 'A' && char <= 'Z') {
            const kch = key[keyIndex++];
            result += String.fromCharCode(((char.charCodeAt(0) - 65 + (kch.charCodeAt(0) - 65)) % 26) + 65); // encrypt eq text + key mod 26
        } else {
            result += char;
        }
    }

    return result;
}

function decryptVigenereAlgo(msg, key) {
    msg = msg.toUpperCase();
    key = generateKey(cleanText(msg).length ? cleanText(msg) : msg, key);

    let result = "";
    let keyIndex = 0;

    for (let i = 0; i < msg.length; i++) {
        const char = msg[i];
        if (char >= 'A' && char <= 'Z') {
            const kch = key[keyIndex++];
            result += String.fromCharCode(((char.charCodeAt(0) - 65 - (kch.charCodeAt(0) - 65) + 26) % 26) + 65);// decrypt eq text - key mod 26
        } else {
            result += char;
        }
    }

    return result;
}

function encryptVigenere() {
    const plain = document.getElementById('vigenere-plain').value;
    const key = document.getElementById('vigenere-key').value;
    document.getElementById('vigenere-cipher').value = encryptVigenereAlgo(plain, key);
}

function decryptVigenere() {
    const cipher = document.getElementById('vigenere-cipher').value;
    const key = document.getElementById('vigenere-key').value;
    document.getElementById('vigenere-plain').value = decryptVigenereAlgo(cipher, key);
}

// Hill Cipher (2x2 Matrix) 
// ==========================================
function matrix2x2Inverse(a, b, c, d) {
    let det = (a * d - b * c) % 26; // determinant eq det=ad−bc mod 26
    det = ((det % 26) + 26) % 26;

    let detInv = modInverse(det, 26);

    if (detInv === null) {
        alert("Matrix is not invertible - choose different values");
        return null;
    }

    let inv_a = ((d * detInv) % 26 + 26) % 26;
    let inv_b = ((-b * detInv) % 26 + 26) % 26;
    let inv_c = ((-c * detInv) % 26 + 26) % 26;
    let inv_d = ((a * detInv) % 26 + 26) % 26;

    return [
        [inv_a, inv_b],
        [inv_c, inv_d]
    ];
}

function hillEncrypt(message, a, b, c, d) {
    if (message.length < 2) {
        return 'Error: Text must be at least 2 characters.';
    }

    let result = "";
    
    for (let i = 0; i < message.length - 1; i += 2) {
        let x1 = message.charCodeAt(i) - 65;
        let x2 = message.charCodeAt(i + 1) - 65;

        let y1 = (a * x1 + b * x2) % 26; // encrypt eq ضرب المصفوفة في ال vector
        let y2 = (c * x1 + d * x2) % 26;

        y1 = ((y1 % 26) + 26) % 26;
        y2 = ((y2 % 26) + 26) % 26;

        result += String.fromCharCode(y1 + 65);
        result += String.fromCharCode(y2 + 65);
    }

    return result;
}

function hillDecrypt(cipher, a, b, c, d) {
    if (cipher.length < 2) {
        return 'Error: Ciphertext must be at least 2 characters.';
    }

    let inverseMatrix = matrix2x2Inverse(a, b, c, d);
    
    if (inverseMatrix === null) {
        return 'Error: Cannot decrypt with this matrix';
    }

    let inv_a = inverseMatrix[0][0];
    let inv_b = inverseMatrix[0][1];
    let inv_c = inverseMatrix[1][0];
    let inv_d = inverseMatrix[1][1];

    let result = "";

    for (let i = 0; i < cipher.length - 1; i += 2) {
        let y1 = cipher.charCodeAt(i) - 65;
        let y2 = cipher.charCodeAt(i + 1) - 65;

        let x1 = (inv_a * y1 + inv_b * y2) % 26;
        let x2 = (inv_c * y1 + inv_d * y2) % 26;

        x1 = ((x1 % 26) + 26) % 26;
        x2 = ((x2 % 26) + 26) % 26;

        result += String.fromCharCode(x1 + 65);
        result += String.fromCharCode(x2 + 65);
    }

    return result;
}

function encryptHill() {
    const plainEl = document.getElementById('hill-plain');
    const cipherEl = document.getElementById('hill-cipher');

    const a = parseInt(document.getElementById('hill-a').value, 10);
    const b = parseInt(document.getElementById('hill-b').value, 10);
    const c = parseInt(document.getElementById('hill-c').value, 10);
    const d = parseInt(document.getElementById('hill-d').value, 10);

    const plain = cleanText(plainEl.value);
    
    if (plain.length < 2) {
        cipherEl.value = 'Error: Text must be at least 2 characters.';
        return;
    }

    const encrypted = hillEncrypt(plain, a, b, c, d);
    cipherEl.value = encrypted;
}

function decryptHill() {
    const plainEl = document.getElementById('hill-plain');
    const cipherEl = document.getElementById('hill-cipher');

    const a = parseInt(document.getElementById('hill-a').value, 10);
    const b = parseInt(document.getElementById('hill-b').value, 10);
    const c = parseInt(document.getElementById('hill-c').value, 10);
    const d = parseInt(document.getElementById('hill-d').value, 10);

    const cipher = cleanText(cipherEl.value);
    
    if (cipher.length < 2) {
        plainEl.value = 'Error: Ciphertext must be at least 2 characters.';
        return;
    }

    const decrypted = hillDecrypt(cipher, a, b, c, d);
    plainEl.value = decrypted;
}

// Affine Cipher
// ==========================================
function encryptAffine() {
    const plainEl = document.getElementById('affine-plain');
    const cipherEl = document.getElementById('affine-cipher');

    const a = parseInt(document.getElementById('affine-a').value, 10);
    const b = parseInt(document.getElementById('affine-b').value, 10);
    const plain = cleanText(plainEl.value);

    cipherEl.value = affineEncrypt(plain, [a, b]);
}

function decryptAffine() {
    const plainEl = document.getElementById('affine-plain');
    const cipherEl = document.getElementById('affine-cipher');

    const a = parseInt(document.getElementById('affine-a').value, 10);
    const b = parseInt(document.getElementById('affine-b').value, 10);
    const cipher = cleanText(cipherEl.value);

    plainEl.value = affineDecrypt(cipher, [a, b]);
}

function affineEncrypt(text, key) {
    let result = "";

    text = text.replace(/ /g, "");

    for (let char of text) {
        let base = char === char.toUpperCase() ? 65 : 97;

        result += String.fromCharCode(
            ((key[0] * (char.charCodeAt(0) - base) + key[1]) % 26) + base // encrypt eq (ax + b) mod 26
        );
    }

    return result;
}

function affineDecrypt(cipher, key) {
    let result = "";
    let aInverse = 0;

    for (let i = 0; i < 26; i++) {
        if ((key[0] * i) % 26 === 1) { 
            aInverse = i;
            break;
        }
    }

    for (let char of cipher) {
        let base = char === char.toUpperCase() ? 65 : 97;

        result += String.fromCharCode(
            ((aInverse * (char.charCodeAt(0) - base - key[1] + 26)) % 26) + base
        );
    }

    return result;
}
// One Time Pad (OTP)
// ==========================================
function encryptOTP() {
    const plainEl = document.getElementById('otp-plain');
    const cipherEl = document.getElementById('otp-cipher');
    const keyStr = document.getElementById('otp-key').value || '';

    const plain = plainEl.value;
    let keyBytes;
    if (!keyStr) {
        keyBytes = generateOTPKey(plain.length);
        document.getElementById('otp-key').value = keyBytes.join(',');
    } else {
        keyBytes = keyStr.split(',').map(n => parseInt(n.trim(), 10)).filter(n => !Number.isNaN(n));
    }

    if (keyBytes.length < plain.length) {
        cipherEl.value = 'Error: OTP key must be at least as long as the message (use Generate or enter comma-separated bytes).';
        return;
    }

    const cipherArr = otpEncrypt(plain, keyBytes.slice(0, plain.length));
    cipherEl.value = cipherArr.join(',');
}

function decryptOTP() {
    const plainEl = document.getElementById('otp-plain');
    const cipherEl = document.getElementById('otp-cipher');
    const keyStr = document.getElementById('otp-key').value || '';

    const cipherArr = cipherEl.value.trim() ? cipherEl.value.split(',').map(n => parseInt(n.trim(), 10)) : [];
    const keyBytes = keyStr.split(',').map(n => parseInt(n.trim(), 10)).filter(n => !Number.isNaN(n));

    if (cipherArr.length === 0) {
        plainEl.value = 'Error: Invalid OTP ciphertext (expected comma-separated numbers).';
        return;
    }
    if (keyBytes.length < cipherArr.length) {
        plainEl.value = 'Error: OTP key must be at least as long as the ciphertext.';
        return;
    }

    const decrypted = otpDecrypt(cipherArr, keyBytes.slice(0, cipherArr.length));
    plainEl.value = decrypted;
}

function generateOTPKey(length) {
    const plainEl = document.getElementById('otp-plain');
    const plain = plainEl ? plainEl.value || '' : '';
    let len = typeof length === 'number' ? length : plain.length;
    if (len === 0) {
        len = 32;
    }

    const key = [];
    for (let i = 0; i < len; i++) {
        key.push(Math.floor(Math.random() * 256));
    }
    const keyInput = document.getElementById('otp-key');
    if (keyInput) keyInput.value = key.join(',');

    return key;
}

function otpEncrypt(text, key) {
    let encrypted = [];

    for (let i = 0; i < text.length; i++) {
        encrypted.push(text.charCodeAt(i) ^ key[i]);
    }

    return encrypted;
}

function otpDecrypt(cipher, key) {
    let decrypted = "";

    for (let i = 0; i < cipher.length; i++) {
        decrypted += String.fromCharCode(cipher[i] ^ key[i]);
    }

    return decrypted;
}
// Substitution Cipher
// ==========================================
function generateSubKey() {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');
    for (let i = alphabet.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [alphabet[i], alphabet[j]] = [alphabet[j], alphabet[i]];
    }
    document.getElementById('sub-key').value = alphabet.join('');
}

function isValidSubKey(key) {
    return key.length === 26 &&
           new Set(key).size === 26 &&
           /^[A-Z]+$/.test(key);
}

function substitutionEncrypt(text, key) {
    key = key.toUpperCase();
    if (!isValidSubKey(key)) {
        return 'Error: Key must be exactly 26 unique letters (A–Z)!';
    }
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    return text.split('').map(char => {
        const idx = alphabet.indexOf(char.toUpperCase());
        if (idx !== -1) {
            const encrypted = key[idx];
            return char === char.toUpperCase() ? encrypted : encrypted.toLowerCase();
        }
        return char;
    }).join('');
}

function substitutionDecrypt(text, key) {
    key = key.toUpperCase();
    if (!isValidSubKey(key)) {
        return 'Error: Key must be exactly 26 unique letters (A–Z)!';
    }
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    return text.split('').map(char => {
        const idx = key.indexOf(char.toUpperCase());
        if (idx !== -1) {
            const decrypted = alphabet[idx];
            return char === char.toUpperCase() ? decrypted : decrypted.toLowerCase();
        }
        return char;
    }).join('');
}

function encryptSubstitution() {
    const plain = document.getElementById('sub-plain').value;
    const key = document.getElementById('sub-key').value;
    document.getElementById('sub-cipher').value = substitutionEncrypt(plain, key);
}

function decryptSubstitution() {
    const cipher = document.getElementById('sub-cipher').value;
    const key = document.getElementById('sub-key').value;
    document.getElementById('sub-plain').value = substitutionDecrypt(cipher, key);
}

// Rail Fence Cipher
// ==========================================
function railFenceEncrypt(text, rails) {
    if (rails < 2) return text;
    const clean = text.replace(/\s+/g, '');
    const rows = Array.from({ length: rails }, () => []);
    let row = 0;
    let direction = 1;
    for (const char of clean) {
        rows[row].push(char);
        if (row === 0) direction = 1;
        if (row === rails - 1) direction = -1;
        row += direction;
    }
    return rows.map(r => r.join('')).join('');
}

function railFenceDecrypt(text, rails) {
    if (rails < 2) return text;
    const length = text.length;
    const route = [];
    let row = 0;
    let direction = 1;
    for (let i = 0; i < length; i++) {
        route.push(row);
        if (row === 0) direction = 1;
        if (row === rails - 1) direction = -1;
        row += direction;
    }
    const rows = Array.from({ length: rails }, () => []);
    let index = 0;
    for (let r = 0; r < rails; r++) {
        for (let i = 0; i < length; i++) {
            if (route[i] === r) {
                rows[r].push(text[index++]);
            }
        }
    }
    let result = '';
    const positions = Array(rails).fill(0);
    for (const r of route) {
        result += rows[r][positions[r]++];
    }
    return result;
}

function encryptRailFence() {
    const plain = document.getElementById('rail-plain').value;
    const rails = parseInt(document.getElementById('rail-rails').value) || 3;
    document.getElementById('rail-cipher').value = railFenceEncrypt(plain, rails);
}

function decryptRailFence() {
    const cipher = document.getElementById('rail-cipher').value;
    const rails = parseInt(document.getElementById('rail-rails').value) || 3;
    document.getElementById('rail-plain').value = railFenceDecrypt(cipher, rails);
}

// Columnar Transposition Cipher
// ==========================================
function columnarEncrypt(text, key) {
    key = cleanText(key);
    if (!key) return 'Error: Key required!';
    const plain = cleanText(text);
    const cols = key.length;
    const rows = Math.ceil(plain.length / cols);
    const matrix = Array.from({ length: rows }, () => Array(cols).fill('X'));
    let index = 0;
    for (let r = 0; r < rows; r++) {
        for (let c = 0; c < cols; c++) {
            matrix[r][c] = plain[index++] || 'X';
        }
    }
    const order = [...key].map((ch, i) => ({ ch, i })).sort((a, b) => a.ch.localeCompare(b.ch) || a.i - b.i);
    return order.map(o => matrix.map(row => row[o.i]).join('')).join('');
}

function columnarDecrypt(text, key) {
    key = cleanText(key);
    if (!key) return 'Error: Key required!';
    const cols = key.length;
    const rows = Math.ceil(text.length / cols);
    const order = [...key].map((ch, i) => ({ ch, i })).sort((a, b) => a.ch.localeCompare(b.ch) || a.i - b.i);
    const matrix = Array.from({ length: rows }, () => Array(cols).fill(''));
    let index = 0;
    for (const o of order) {
        for (let r = 0; r < rows; r++) {
            matrix[r][o.i] = text[index++] || 'X';
        }
    }
    return matrix.map(row => row.join('')).join('').replace(/X+$/g, '');
}

function encryptColumnar() {
    const plain = document.getElementById('columnar-plain').value;
    const key = document.getElementById('columnar-key').value;
    document.getElementById('columnar-cipher').value = columnarEncrypt(plain, key);
}

function decryptColumnar() {
    const cipher = document.getElementById('columnar-cipher').value;
    const key = document.getElementById('columnar-key').value;
    document.getElementById('columnar-plain').value = columnarDecrypt(cipher, key);
}

// RSA Cipher
// ==========================================
let rsaPrivateD = null;

function isPrimeBigInt(value) {
    if (value < 2n) return false;
    if (value % 2n === 0n) return value === 2n;
    for (let i = 3n; i * i <= value; i += 2n) {
        if (value % i === 0n) return false;
    }
    return true;
}

function generateRSAKeys() {
    const p = BigInt(document.getElementById('rsa-p').value || 0);
    const q = BigInt(document.getElementById('rsa-q').value || 0);
    const e = BigInt(document.getElementById('rsa-e').value || 65537);
    const output = document.getElementById('rsa-keys');
    if (!isPrimeBigInt(p) || !isPrimeBigInt(q) || p === q) {
        output.value = 'Error: p and q must be distinct primes.';
        rsaPrivateD = null;
        return;
    }
    const n = p * q;
    const phi = (p - 1n) * (q - 1n);
    if (gcdBigInt(e, phi) !== 1n) {
        output.value = 'Error: e must be coprime with φ(n).';
        rsaPrivateD = null;
        return;
    }
    rsaPrivateD = modInverseBigInt(e, phi);
    output.value = `Public: (n=${n}, e=${e})\nPrivate: d=${rsaPrivateD}`;
}

function encryptRSA() {
    const text = document.getElementById('rsa-plain').value;
    const e = BigInt(document.getElementById('rsa-e').value || 17);
    const p = BigInt(document.getElementById('rsa-p').value || 0);
    const q = BigInt(document.getElementById('rsa-q').value || 0);
    const n = p * q;
    if (n <= 0n) {
        document.getElementById('rsa-cipher').value = 'Error: Invalid RSA modulus.';
        return;
    }
    document.getElementById('rsa-cipher').value = text.split('').map(ch => modPow(BigInt(ch.codePointAt(0)), e, n).toString()).join(' '); // encrypt eq c = m^e mod n
}

function decryptRSA() {
    const cipher = document.getElementById('rsa-cipher').value.trim();
    const d = rsaPrivateD;
    const p = BigInt(document.getElementById('rsa-p').value || 0);
    const q = BigInt(document.getElementById('rsa-q').value || 0);
    const n = p * q;
    if (!cipher || n <= 0n || d === null) {
        document.getElementById('rsa-plain').value = 'Error: Generate RSA keys first.';
        return;
    }
    try {
        document.getElementById('rsa-plain').value = cipher.split(' ').map(block => String.fromCharCode(Number(modPow(BigInt(block), d, n)))).join(''); // decrypt eq m = c^d mod n
    } catch (error) {
        document.getElementById('rsa-plain').value = 'Error: Invalid RSA ciphertext.';
    }
}

// Diffie-Hellman Cipher
// ==========================================
function computeDiffieHellman() {
    const prime = BigInt(document.getElementById('dh-prime').value || 0);
    const base = BigInt(document.getElementById('dh-base').value || 0);
    const privateA = BigInt(document.getElementById('dh-private-a').value || 0);
    const privateB = BigInt(document.getElementById('dh-private-b').value || 0);
    if (prime <= 1n || base < 2n || privateA <= 0n || privateB <= 0n) {
        document.getElementById('dh-public').value = 'Error: Use valid prime, base, and private values.';
        document.getElementById('dh-secret').value = '';
        return;
    }
    const publicA = modPow(base, privateA, prime);
    const publicB = modPow(base, privateB, prime);
    const sharedA = modPow(publicB, privateA, prime);
    const sharedB = modPow(publicA, privateB, prime);
    document.getElementById('dh-public').value = `Public A: ${publicA}\nPublic B: ${publicB}`;
    document.getElementById('dh-secret').value = sharedA === sharedB ? `Shared Secret: ${sharedA}` : 'Error: secrets do not match.';
}

// AES Cipher
// ==========================================
async function getAesCryptoKey(key) {
    return window.crypto.subtle.importKey(
        'raw',
        normalizeAesKey(key),
        'AES-CBC',
        false,
        ['encrypt', 'decrypt']
    );
}

function generateAESIv() {
    const iv = window.crypto.getRandomValues(new Uint8Array(16));
    document.getElementById('aes-iv').value = bytesToHex(iv);
}

async function encryptAES() {
    const plain = document.getElementById('aes-plain').value;
    const key = document.getElementById('aes-key').value;
    let ivBytes = hexStringToBytes(document.getElementById('aes-iv').value || '');
    if (!ivBytes || ivBytes.length !== 16) {
        ivBytes = window.crypto.getRandomValues(new Uint8Array(16));
        document.getElementById('aes-iv').value = bytesToHex(ivBytes);
    }
    try {
        const cryptoKey = await getAesCryptoKey(key);
        const encrypted = await window.crypto.subtle.encrypt({ name: 'AES-CBC', iv: ivBytes }, cryptoKey, stringToBytes(plain));
        document.getElementById('aes-cipher').value = arrayBufferToBase64(encrypted);
    } catch (error) {
        document.getElementById('aes-cipher').value = 'Error: AES encryption failed.';
    }
}

async function decryptAES() {
    const cipher = document.getElementById('aes-cipher').value.trim();
    const key = document.getElementById('aes-key').value;
    const ivBytes = hexStringToBytes(document.getElementById('aes-iv').value || '');
    if (!cipher || !ivBytes || ivBytes.length !== 16) {
        document.getElementById('aes-plain').value = 'Error: Invalid IV or ciphertext.';
        return;
    }
    try {
        const cryptoKey = await getAesCryptoKey(key);
        const decrypted = await window.crypto.subtle.decrypt({ name: 'AES-CBC', iv: ivBytes }, cryptoKey, base64ToArrayBuffer(cipher));
        document.getElementById('aes-plain').value = bytesToString(new Uint8Array(decrypted));
    } catch (error) {
        document.getElementById('aes-plain').value = 'Error: AES decryption failed.';
    }
}

// DES Cipher
// ==========================================
function encryptDES() {
    const plain = document.getElementById('des-plain').value;
    const key = document.getElementById('des-key').value.padEnd(8, '\0').substr(0, 8);
    if (!key || key.length !== 8) {
        document.getElementById('des-cipher').value = 'Error: DES key must be 8 characters.';
        return;
    }
    document.getElementById('des-cipher').value = encryptDesText(plain, key);
}

function decryptDES() {
    const cipher = document.getElementById('des-cipher').value.trim();
    const key = document.getElementById('des-key').value.padEnd(8, '\0').substr(0, 8);
    if (!key || key.length !== 8) {
        document.getElementById('des-plain').value = 'Error: DES key must be 8 characters.';
        return;
    }
    document.getElementById('des-plain').value = decryptDesText(cipher, key);
}

// Hash Function
// ==========================================
async function hashMessage() {
    const text = document.getElementById('hash-input').value;
    const algo = document.getElementById('hash-algo').value;
    try {
        const digest = await window.crypto.subtle.digest(algo, stringToBytes(text));
        document.getElementById('hash-output').value = bytesToHex(digest);
    } catch (error) {
        document.getElementById('hash-output').value = 'Error: Hash failed.';
    }
}