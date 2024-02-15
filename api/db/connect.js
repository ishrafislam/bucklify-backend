const mongoose = require('mongoose')
const config = require('../config/config')

mongoose.connect(config.MONGODB_URI)
.then(() => console.log('Connected to MongoDB'))
.catch(error => console.log('Error connecting to MongoDB: ', error))

module.exports = mongoose
