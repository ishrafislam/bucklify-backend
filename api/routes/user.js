const authMiddleware = require('../middleware/auth')
const userController = require('../controllers/user')
const express = require('express')
const router = express.Router()

router.get('/v1/info', authMiddleware.authenticate, userController.userInfo)

module.exports = router
