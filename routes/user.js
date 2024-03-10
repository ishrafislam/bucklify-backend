const authMiddleware = require('../middleware/auth')
const userController = require('../controllers/user')
const express = require('express')
const router = express.Router()

router.get('/v1/info', authMiddleware.authenticate, userController.userInfo)
router.patch('/v1/reset-password', authMiddleware.authenticate, userController.resetPassword)
router.patch('/v1/2fa-request', authMiddleware.authenticate, userController.update2FARequest)
router.patch('/v1/2fa-verify', authMiddleware.authenticate, userController.update2FAVerify)

module.exports = router
