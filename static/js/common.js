// Common utilities and encryption

let encryptionKey = null;
let sharedKey = 'tvclipboard-default-key'; // Default shared key

// Simple encryption using Web Crypto API
async function getKey() {
    if (!encryptionKey) {
        // Derive key from shared key string
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            enc.encode(sharedKey),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );
        encryptionKey = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: enc.encode("tvclipboard-salt"),
                iterations: 1000,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    }
    return encryptionKey;
}

async function encryptMessage(text) {
    const key = await getKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(text);
    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encoded
    );

    // Combine IV and encrypted data
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);

    // Convert to base64
    return btoa(String.fromCharCode(...combined));
}

async function decryptMessage(base64) {
    const key = await getKey();
    const combined = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    const iv = combined.slice(0, 12);
    const encrypted = combined.slice(12);

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encrypted
    );

    return new TextDecoder().decode(decrypted);
}

function getWebSocketURL() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    return `${protocol}//${host}/ws`;
}

function getPublicURL() {
    return window.location.href;
}
