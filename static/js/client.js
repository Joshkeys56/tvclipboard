// Client-specific functionality

async function sendText() {
    const input = document.getElementById('input');
    const content = input.value.trim();

    if (!content) {
        alert('Please enter some text');
        return;
    }

    if (ws && ws.readyState === WebSocket.OPEN) {
        try {
            // Encrypt the content
            const encrypted = await encryptMessage(content);
            const message = {
                type: 'text',
                content: encrypted
            };
            ws.send(JSON.stringify(message));
            console.log('Sent message:', message);
            input.value = '';
        } catch (error) {
            console.error('Encryption failed:', error);
            // Fallback to sending unencrypted
            const message = {
                type: 'text',
                content: content
            };
            ws.send(JSON.stringify(message));
            console.log('Sent unencrypted message:', message);
            input.value = '';
        }
    } else {
        alert('Not connected. Please wait...');
    }
}

function clearInput() {
    document.getElementById('input').value = '';
}

function copyFromClipboard() {
    if (navigator.clipboard && navigator.clipboard.readText) {
        navigator.clipboard.readText()
            .then(text => {
                document.getElementById('input').value = text;
            })
            .catch(err => {
                console.error('Failed to read clipboard:', err);
                alert('Clipboard access blocked.\n\nOn mobile: Long-press in textarea and select "Paste"\n\nOn desktop: Use Ctrl+V / Cmd+V');
            });
    } else {
        alert('Clipboard access not supported.\nOn mobile: Long-press in textarea and select "Paste"');
        document.getElementById('input').focus();
    }
}

// Allow Enter key to send (with Shift+Enter for new line)
document.addEventListener('DOMContentLoaded', function() {
    const input = document.getElementById('input');
    if (input) {
        input.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendText();
            }
        });
    }
});
