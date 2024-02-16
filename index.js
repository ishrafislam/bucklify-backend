require('dotenv').config()

const authRouter = require('./routes/auth')
const userRouter = require('./routes/user')

const express = require('express')
const app = express()
const port = 3000

app.use(express.json())

app.use('/auth', authRouter)
app.use('/user', userRouter)

app.listen(port, () => {
    console.log(`App running on port ${port}`)
})

module.exports = app
