const authController = require('../controllers/auth')
const express = require('express')
const router = express.Router()

router.post('/v1/register', authController.registerUser)
router.post('/v1/login', authController.loginUser)
router.post('/v1/refresh-token', authController.refreshToken)

module.exports = router
