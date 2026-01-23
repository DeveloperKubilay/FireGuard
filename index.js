require('dotenv').config();
const axios = require('axios');
const kubitdb = require('kubitdb');
const db = new kubitdb('./data');

async function getToken() {
    if (process.env.BOT_TOKEN) return process.env.BOT_TOKEN;
    if (db.has('tokens')) {
        const arr = db.get('tokens');
        if (Array.isArray(arr) && arr.length) return arr[0].access_token || arr[0].accessToken || null;
    }
    return null;
}

async function send(channel, message) {
    const token = await getToken();
    if (!token) throw new Error('No token found. Set BOT_TOKEN or have tokens in ./data');
    const body = { content: String(message).slice(0, 500), type: 'bot' };
    try {
        const r = await axios.post('https://api.kick.com/public/v1/chat', body, {
            headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
        });
        console.log('OK', r.data);
    } catch (e) {
        console.error(e.response ? e.response.data : e.message);
        process.exitCode = 1;
    }
}

const channel = process.argv[2] || '';
const message = process.argv.slice(3).join(' ') || 'test';
if (!channel) {
    console.error('Usage: node send_test.js <channel> <message>');
    process.exit(1);
}

send(channel, message);
