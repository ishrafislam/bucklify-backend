const db = require('../db/connect')

const userSchema = new db.Schema({
    firstName: String,
    lastName: String,
    email: String,
    password: String,
    verified: Boolean,
    twoFAEnabled: Boolean,
})

module.exports = db.model('User', userSchema)
