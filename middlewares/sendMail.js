const nodeMailer = require('nodemailer');
const transport = nodeMailer.createTransport(
    {
        // host: 'smtp.gmail.com',
        service: 'gmail',
        auth: {
            user: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
            pass: process.env.NODE_CODE_SENDING_EMAIL_PASSWORD
        }
    }
)

module.exports=transport;