// Common utilities and encryption

let encryptionKey = null;
let sharedKey = 'tvclipboard-default-key'; // Default shared key
let cryptoAvailable = window.crypto && window.crypto.subtle;

console.log('Web Crypto API available:', cryptoAvailable);
if (!cryptoAvailable) {
    console.warn('Note: Web Crypto API is not available. This happens when accessing via HTTP (not HTTPS) and not on localhost. Messages will be sent unencrypted.');
}

// Simple encryption using Web Crypto API
async function getKey() {
    if (!cryptoAvailable) {
        console.warn('Web Crypto API not available (needs HTTPS or localhost). Messages will be unencrypted.');
        return null;
    }

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
    if (!cryptoAvailable) {
        console.warn('Web Crypto API not available. Sending unencrypted message.');
        return text; // Return plain text if crypto not available
    }

    const key = await getKey();
    if (!key) return text; // Fallback if key generation fails

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
    if (!cryptoAvailable) {
        console.warn('Web Crypto API not available. Received unencrypted message.');
        return base64; // Return as-is if crypto not available
    }

    const key = await getKey();
    if (!key) return base64; // Fallback if key generation fails

    try {
        const combined = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
        const iv = combined.slice(0, 12);
        const encrypted = combined.slice(12);

        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encrypted
        );

        return new TextDecoder().decode(decrypted);
    } catch (error) {
        console.error('Decryption failed:', error);
        throw error;
    }
}

function getWebSocketURL() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    return `${protocol}//${host}/ws`;
}

function getPublicURL() {
    return window.location.href;
}

function formatTime(seconds) {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
}
