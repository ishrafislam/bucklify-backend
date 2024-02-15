const mongoose = require('mongoose')

mongoose.connect('mongodb://localhost:27017/bucklify')
.then(() => console.log('Connected to MongoDB'))
.catch(error => console.log('Error connecting to MongoDB: ', error))

const userSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: String,
    password: String
})

module.exports = mongoose.model('User', userSchema)
