const db = require('../db/connect')

const otpSchema = new db.Schema({
    userId: String,
    referenceId: String,
    value: String,
    expireAt: String
})

module.exports = db.model('OTP', otpSchema)
