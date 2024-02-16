const jwt = require('jsonwebtoken')
const User = require('../models/user')
const config = require('../config/config')

const authMiddleware = {
    async authenticate(req, res, next) {
        const authHeader = req.headers.authorization
    
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({success: false, data: {message: 'Authorization header missing'}})
        }
    
        const accessToken = authHeader.split(' ')[1]
    
        jwt.verify(accessToken, config.ACCESS_TOKEN_SECRET, async (error, decodedToken) => {
            if (error) {
                console.log(error)
                return res.status(401).json({success: false, data: {message: 'Invalid access token'}})
            }
    
            try {
                const user = await User.findById(decodedToken.id)
                if (!user) {
                    return res.status(400).json({success: false, data: {message: 'User not found'}})
                }
    
                req.user = user
                next()
            } catch (error) {
                console.log('Error retrieving user data:', error)
                return res.status(500).json({success: false, data: {message: 'Internal server error'}})
            }
        })
    }
}

module.exports = authMiddleware
