require('dotenv').config();
const express = require('express');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const TOKENS_FILE = path.join(__dirname, 'tokens.json');

const CLIENT_ID = process.env.ID;
const CLIENT_SECRET = process.env.SEC;
const SCOPE = process.env.SCOPE || 'user:read events:subscribe chat:write moderation:ban moderation:chat_message:manage';
const PORT = process.env.PORT || 3000;
const REDIRECT_URI = process.env.REDIRECT_URI || `http://localhost:${PORT}/callback`;

if (!CLIENT_ID || !CLIENT_SECRET) {
    console.error('Missing ID or SEC in .env');
    process.exit(1);
}

const app = express();

const crypto = require('crypto');

function base64url(buffer) {
    return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const pkceStore = new Map();

app.get('/', (req, res) => res.send(`<a href="/login">Kick ile giriş yap</a>`));

app.get('/login', (req, res) => {
    const state = base64url(crypto.randomBytes(12));
    const code_verifier = base64url(crypto.randomBytes(48));
    const sha = crypto.createHash('sha256').update(code_verifier).digest();
    const code_challenge = base64url(sha);
    pkceStore.set(state, { code_verifier, created: Date.now() });
    const url = `https://id.kick.com/oauth/authorize?client_id=${encodeURIComponent(CLIENT_ID)}&response_type=code&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=${encodeURIComponent(SCOPE)}&code_challenge=${encodeURIComponent(code_challenge)}&code_challenge_method=S256&state=${encodeURIComponent(state)}`;
    res.redirect(url);
});

app.get('/callback', async (req, res) => {
    const code = req.query.code;
    const state = req.query.state;
    if (!code) return res.status(400).send('No code provided');
    if (!state) return res.status(400).send('No state provided');
    const entry = pkceStore.get(state);
    if (!entry) return res.status(400).send('Invalid or expired state');
    pkceStore.delete(state);
    try {
        const params = new URLSearchParams({
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            grant_type: 'authorization_code',
            code,
            redirect_uri: REDIRECT_URI,
            code_verifier: entry.code_verifier
        });
        const tokenRes = await axios.post('https://id.kick.com/oauth/token', params.toString(), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });
            const data = tokenRes.data;
            console.log('Tokens:', data);
            try {
                fs.writeFileSync(TOKENS_FILE, JSON.stringify(data, null, 2));
                console.log('Tokens saved to', TOKENS_FILE);
            } catch (e) {
                console.error('Failed to save tokens:', e.message);
            }
            res.send('Token alındı ve kaydedildi. Konsolu kontrol et.');
    } catch (err) {
        console.error(err.response ? err.response.data : err.message);
        res.status(500).send('Token exchange failed');
    }
});

app.listen(PORT, () => {
    console.log(`Aç: http://localhost:${PORT}/login`);
    console.log(`Listening on http://localhost:${PORT}`);
});

    function loadTokens() {
        try { return JSON.parse(fs.readFileSync(TOKENS_FILE,'utf8')); } catch (e) { return null; }
    }

    async function refreshTokens() {
        const tokens = loadTokens();
        if (!tokens || !tokens.refresh_token) throw new Error('No refresh token saved');
        const params = new URLSearchParams({
            grant_type: 'refresh_token',
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            refresh_token: tokens.refresh_token
        });
        const r = await axios.post('https://id.kick.com/oauth/token', params.toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
        try { fs.writeFileSync(TOKENS_FILE, JSON.stringify(r.data, null, 2)); } catch (e) { console.error('Failed to save refreshed tokens:', e.message); }
        return r.data;
    }

    async function resolveBroadcasterId(channel) {
        if (!channel) return null;
        if (/^\d+$/.test(channel)) return Number(channel);
        const tokens = loadTokens();
        console.log(tokens);
        const res = await axios.get(`https://api.kick.com/public/v1/channels?slug=${encodeURIComponent(channel)}`, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
        const list = res.data && res.data.data ? res.data.data : res.data;
        if (!list || !list.length) throw new Error('Channel not found');
        return list[0].broadcaster_user_id || list[0].broadcaster_user_id;
    }

    async function sendMessage(channel, text) {
        let tokens = loadTokens();
        if (!tokens) throw new Error('No tokens available. Authenticate via /login first');
        try {
            const currentUserId = await getCurrentUserId(tokens.access_token).catch(()=>null);
            const broadcaster_id = channel ? await resolveBroadcasterId(channel) : null;
            if (channel && !broadcaster_id) throw new Error('Channel not found');
            if (channel && currentUserId && Number(currentUserId) === Number(broadcaster_id)) {
                const body = { broadcaster_user_id: broadcaster_id, content: text, type: 'user' };
                const r = await axios.post(`https://api.kick.com/public/v1/chat`, body, { headers: { Authorization: `Bearer ${tokens.access_token}`, 'Content-Type': 'application/json' } });
                return r.data;
            }
            if (channel && (!currentUserId || Number(currentUserId) !== Number(broadcaster_id))) {
                throw { message: 'Unauthorized to post to that channel with current token. Token must belong to the channel owner.' };
            }
            const body = { content: text, type: 'bot' };
            const r = await axios.post(`https://api.kick.com/public/v1/chat`, body, { headers: { Authorization: `Bearer ${tokens.access_token}`, 'Content-Type': 'application/json' } });
            return r.data;
        } catch (err) {
            if (err.response && (err.response.status === 401 || err.response.status === 403)) {
                tokens = await refreshTokens();
                const currentUserId = await getCurrentUserId(tokens.access_token).catch(()=>null);
                const broadcaster_id = channel ? await resolveBroadcasterId(channel) : null;
                if (channel && currentUserId && Number(currentUserId) === Number(broadcaster_id)) {
                    const body = { broadcaster_user_id: broadcaster_id, content: text, type: 'user' };
                    const retry = await axios.post(`https://api.kick.com/public/v1/chat`, body, { headers: { Authorization: `Bearer ${tokens.access_token}`, 'Content-Type': 'application/json' } });
                    return retry.data;
                }
                if (channel && (!currentUserId || Number(currentUserId) !== Number(broadcaster_id))) {
                    throw { message: 'Unauthorized to post to that channel with current token even after refresh.' };
                }
                const body = { content: text, type: 'bot' };
                const retry = await axios.post(`https://api.kick.com/public/v1/chat`, body, { headers: { Authorization: `Bearer ${tokens.access_token}`, 'Content-Type': 'application/json' } });
                return retry.data;
            }
            throw err;
        }
    }

    async function getCurrentUserId(accessToken) {
        if (!accessToken) return null;
        try {
            const r = await axios.get('https://api.kick.com/public/v1/users', { headers: { Authorization: `Bearer ${accessToken}` } });
            const data = r.data && r.data.data ? r.data.data : r.data;
            if (Array.isArray(data) && data.length>0) return data[0].user_id || data[0].broadcaster_user_id || null;
            if (data && data.user_id) return data.user_id;
            return null;
        } catch (e) { return null; }
    }

    app.get('/send', async (req, res) => {
        const channel = req.query.channel;
        const text = req.query.text;
        if (!channel || !text) return res.status(400).send('Provide channel and text query params');
        try {
            const result = await sendMessage(channel, text);
            res.json({ ok:true, result });
        } catch (err) {
            res.status(500).json({ ok:false, error: err.response ? err.response.data : err.message });
        }
    });




// manual test send removed; use /send?channel=slug&text=... endpoint