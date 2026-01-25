const axios = require('axios');
const crypto = require('crypto');
const express = require('express');
const kubitdb = require('kubitdb');

class KickApi {
    constructor({ clientId, clientSecret, dbPath, app,port } = {}) {
        this.clientId = clientId || process.env.CLIENT_ID;
        this.clientSecret = clientSecret || process.env.CLIENT_SECRET;
        this.db = new kubitdb(dbPath || './data');
        this.UserDatas = new Map();
        if (this.db.has('tokens')) {
            this.db.get('tokens').forEach(tokenData => {
                if (tokenData && tokenData.username) {
                    if ((tokenData.expires_at === undefined || tokenData.expires_at === null) && tokenData.expires_in) {
                        tokenData.expires_at = Date.now() + tokenData.expires_in * 1000;
                    }
                    this.UserDatas.set(tokenData.username, tokenData);
                }
            });
        }


        if (!app) {
            app = express();
            app.listen(port || 3000, () => {
                console.log(`Listening on http://localhost:${port || 3000}`);
            });
        }

        function base64url(buffer) {
            return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        }

        const pkceStore = new Map();

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




    }
    async getToken() {
        if (this.db.has('tokens')) {
            const arr = this.db.get('tokens');
            if (Array.isArray(arr) && arr.length) return arr[0].access_token || arr[0].accessToken || null;
        }
        return null;
    }

    async checkRefreshNeeded(channel) {
        if (!channel) return await this.getToken();
        let tokens = this.UserDatas.get(channel);
        const now = Date.now();
        if (!tokens) return await this.getToken();
        if (!tokens.expires_at && tokens.expires_in) tokens.expires_at = now + tokens.expires_in * 1000;
        if (!tokens.expires_at) {
            if (tokens.refresh_token) {
                const refreshed = await this.refreshTokens(channel);
                return refreshed.access_token || refreshed.accessToken || null;
            }
            return tokens.access_token || tokens.accessToken || null;
        }
        if (tokens.expires_at <= now + 60 * 1000) {
            const refreshed = await this.refreshTokens(channel);
            return refreshed.access_token || refreshed.accessToken || null;
        }
        return tokens.access_token || tokens.accessToken || null;
    }

    async refreshTokens(channel) {
        const tokens = this.UserDatas.get(channel);
        if (!tokens || !tokens.refresh_token) throw new Error('No refresh token saved');
        const params = new URLSearchParams({
            grant_type: 'refresh_token',
            client_id: this.clientId,
            client_secret: this.clientSecret,
            refresh_token: tokens.refresh_token
        });
        const r = await axios.post('https://id.kick.com/oauth/token', params.toString(), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
        const data = r.data;
        if (data.expires_in) data.expires_at = Date.now() + data.expires_in * 1000;
        data.username = channel;
        this.UserDatas.set(channel, data);
        const existing = this.db.has('tokens') ? this.db.get('tokens') : [];
        this.db.set('tokens', existing.filter(t => t.username !== channel).concat([data]));
        return r.data;
    }

    async send(channel, message) {
        const token = await this.checkRefreshNeeded(channel);
        if (!token) throw new Error('No token found. Set BOT_TOKEN or have tokens in ./data');
        const body = { content: String(message).slice(0, 500), type: 'bot' };
        const r = await axios.post('https://api.kick.com/public/v1/chat', body, {
            headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
        });
        return r.data;
    }
}

module.exports = KickApi;