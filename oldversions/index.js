require('dotenv').config();
const express = require('express');
const axios = require('axios');
const kubitdb = require('kubitdb');
const db = new kubitdb('./data');

const CLIENT_ID = process.env.ID;
const CLIENT_SECRET = process.env.SEC;
const SCOPE = 'user:read events:subscribe chat:write moderation:ban moderation:chat_message:manage channel:read';
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
        data.userdata = await getCurrentUserId(data.access_token);
        data.username = data.userdata ? data.userdata.name : 'unknown';
        UserDatas.set(data.username, data);
        db.set('tokens', db.get('tokens').filter(t => t.username !== data.username).concat([data]));
        console.log('Tokens:', data);

        res.send('Token alındı. Konsolu kontrol et.');
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
        return r.data?.data[0];
    } catch (e) { return null; }
}


async function isChannelLive(channel) {
    const tokens = UserDatas.get(channel);
    if (!tokens) return;
    try {
        const { data } = await axios.get(`https://api.kick.com/public/v1/channels?slug=${channel}`, {
            headers: { 'Authorization': `Bearer ${tokens.access_token}` }
        });
        const channelData = data.data && data.data[0];
        const isLive = channelData && channelData.stream && channelData.stream.is_live;
        return !!isLive;
    } catch (e) {
        console.error('Error checking live status:', e.response ? e.response.data : e.message);
    }

    return false;
}

app.get('/islive', async (req, res) => {
    const channel = req.query.channel;
    const live = await isChannelLive(channel);
    res.json({ channel, is_live: live });
});


async function getUserBySlug(slug) {
    try {
        const r = await axios.get(`https://api.kick.com/public/v1/users?slug=${encodeURIComponent(slug)}`);
        return r.data && r.data.data && r.data.data[0];
    } catch (e) { return null; }
}

async function postChatMessage(targetChannel, content, type = 'user', authOwner = null) {
    authOwner = authOwner || targetChannel;
    const tokens = UserDatas.get(authOwner);
    if (!tokens || !tokens.access_token) throw new Error('No token for auth owner');
    const body = { content: content.slice(0, 500), type };
    if (type === 'user') {
        let broadcasterId = tokens.userdata && (tokens.userdata.id || tokens.userdata.user_id || tokens.userId || tokens.user_id);
        if (!broadcasterId) {
            const user = await getUserBySlug(targetChannel);
            broadcasterId = user && (user.id || user.user_id);
        }
        if (!broadcasterId) throw new Error('Missing broadcaster_user_id');
        body.broadcaster_user_id = broadcasterId;
    }

    try {
        const r = await axios.post('https://api.kick.com/public/v1/chat', body, {
            headers: { Authorization: `Bearer ${tokens.access_token}`, 'Content-Type': 'application/json' }
        });
        return r.data;
    } catch (err) {
        const status = err.response && err.response.status;
        if (status === 401 && tokens.refresh_token) {
            await refreshTokens(authOwner);
            const refreshed = UserDatas.get(authOwner);
            if (!refreshed || !refreshed.access_token) throw err;
            const r2 = await axios.post('https://api.kick.com/public/v1/chat', body, {
                headers: { Authorization: `Bearer ${refreshed.access_token}`, 'Content-Type': 'application/json' }
            });
            return r2.data;
        }
        throw err;
    }
}

app.get('/send', async (req, res) => {
    const channel = req.query.channel;
    const text = req.query.text;
    const as = req.query.as || 'user';
    const tokenFor = req.query.token_for || req.query.token || null;
    if (!channel) return res.status(400).send('No channel provided');
    if (!text) return res.status(400).send('No text provided');
    try {
        const data = await postChatMessage(channel, text, as, tokenFor);
        res.json({ ok: true, data });
    } catch (e) {
        console.error(e.response ? e.response.data : e.message);
        res.status(500).json({ ok: false, error: e.response ? e.response.data : e.message });
    }
});
//http://localhost:3000/send?channel=Dead_lock_yk&text=Merhaba%20dunya

