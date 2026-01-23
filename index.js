require('dotenv').config();
const express = require('express');
const axios = require('axios');
const kubitdb = require('kubitdb');
const db = new kubitdb('./data');

const CLIENT_ID = process.env.ID;
const CLIENT_SECRET = process.env.SEC;
const SCOPE = 'user:read events:subscribe chat:write moderation:ban moderation:chat_message:manage';
const REDIRECT_URI = `http://localhost:3000/callback`;


const app = express();
const crypto = require('crypto');

function base64url(buffer) {
    return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const pkceStore = new Map();
const UserDatas = new Map();

if (db.has('tokens')) db.get('tokens').forEach(tokenData => {
    if (tokenData && tokenData.username) {
        UserDatas.set(tokenData.username, tokenData);
    }
});

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
        data.username = await getCurrentUserId(data.access_token);
        console.log(params.toString());
        UserDatas.set(data.username, data);
        db.push('tokens', data);
        console.log('Tokens:', data);
        res.send('Token alındı ve kaydedildi. Konsolu kontrol et.');
    } catch (err) {
        console.error(err.response ? err.response.data : err.message);
        res.status(500).send('Token exchange failed');
    }
});

app.listen(3000, () => {
    console.log(`Aç: http://localhost:3000/login`);
    console.log(`Listening on http://localhost:3000`);
});


async function refreshTokens(channel) {
    const tokens = UserDatas.get(channel);
    if (!tokens || !tokens.refresh_token) throw new Error('No refresh token saved');
    const params = new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        refresh_token: tokens.refresh_token
    });
    const r = await axios.post('https://id.kick.com/oauth/token', params.toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    const data = r.data;
    data.username = channel;
    UserDatas.set(channel, data);
    db.set('tokens', db.get('tokens').filter(t => t.username !== channel).concat([data]));

    return r.data;
}


async function getCurrentUserId(token) {
    if (!token) return null;
    try {
        const r = await axios.get('https://api.kick.com/public/v1/users', { headers: { Authorization: `Bearer ${token}` } });
        return r.data?.data[0]?.name;
    } catch (e) { return null; }
}

app.get('/send', async (req, res) => {
    const channel = req.query.channel;
    const text = req.query.text;
    if (!channel) return res.status(400).send('No channel provided');
    if (!text) return res.status(400).send('No text provided');

    console.log(await resolveBroadcasterId(channel));
});
//http://localhost:3000/send?channel=Dead_lock_yk&text=Merhaba%20dunya

