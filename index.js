const KickApi = require('./kickApi');

(async () => {
    const bot = new KickApi({ 
        clientId: process.env.CLIENT_ID, 
        clientSecret: process.env.CLIENT_SECRET 
    });
    await bot.send('channel name', 'Your message here');

})();