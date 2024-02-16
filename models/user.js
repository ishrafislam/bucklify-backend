const mongoose = require('mongoose')
const db = require('../db/connect')

const userSchema = new db.Schema({
    firstName: String,
    lastName: String,
    email: String,
    password: String
})

module.exports = db.model('User', userSchema)
