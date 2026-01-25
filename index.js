const KickApi = require('./kickApi');

(async () => {
    const bot = new KickApi({ 
        clientId: process.env.CLIENT_ID, 
        clientSecret: process.env.CLIENT_SECRET 
    });
    //await bot.send('Dead_lock_yk', 'Your message here');

})();