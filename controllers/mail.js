const mailer = require('nodemailer')
const config = require('../config/config')

const transporter = mailer.createTransport({
    service: "gmail",
    auth: {
        user: config.MAIL_USER,
        pass: config.MAIL_PASSWORD
    }
})

const mailController = {
    async sendMail(to, subject, body) {
        transporter.sendMail({
            from: 'Bucklify <bucklify@gmail.com>',
            to,
            subject,
            text: body
        })
    }
}

module.exports = mailController
