const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const User = require('../models/user')
const OTP = require('../models/otp')
const config = require('../config/config')
const mailController = require('./mail')
const otpController = require('./otp')

const authController = {
    async registerUser(req, res) {
        try {
            const { firstName, lastName, email, password } = req.body
            const existingUser = await User.findOne({ email })

            if (existingUser && existingUser.verified) {
                return res.status(400).json({ success: false, data: { message: 'User exists for the provided email' } })
            }

            const newUser = new User({
                firstName,
                lastName,
                email,
                password: await bcrypt.hash(password, 5),
                verified: false,
                twoFAEnabled: false,
            })

            newUser.save()

            let dateTime = new Date()

            const newOtp = new OTP({
                userId: newUser._id,
                value: otpController.generateOtp(true),
                referenceId: otpController.generateRef(),
                expireAt: dateTime.setMinutes(dateTime.getMinutes() + 5)
            })

            newOtp.save()

            mailController.sendMail(newUser.email, 'Email verification', `Your verification code is ${newOtp.value}`)

            res.status(200).json(
                {
                    success: true,
                    data: {
                        message: 'OTP sent to your email',
                        otpReference: newOtp.referenceId,
                        expireAt: newOtp.expireAt,
                    }
                }
            )
        } catch (error) {
            console.error('Error registering user:', error)
            res.status(500).json({ success: false, data: { message: 'Internal server error' } })
        }
    },
    async confirmRegister(req, res) {
        try {
            const { referenceId, otp } = req.body
            const existingOtp = await OTP.findOne({ referenceId })

            if (!existingOtp) {
                return res.status(400).json({ success: false, data: { message: 'OTP not found by provided reference ID' } })
            }

            const currentDateTime = new Date()
            const otpExpireTime = new Date(existingOtp.expireAt)

            if (currentDateTime >= otpExpireTime) {
                return res.status(400).json({ success: false, data: { message: 'OTP expired' } })
            }

            if (existingOtp.value != otp) {
                return res.status(400).json({ success: false, data: { message: 'Wrong OTP provided' } })
            }

            const user = await User.findById(existingOtp.userId)
            user.verified = true
            user.save()

            const accessToken = jwt.sign({ id: user._id }, config.ACCESS_TOKEN_SECRET, { expiresIn: config.ACCESS_TOKEN_EXPIRY })
            const refreshToken = jwt.sign({ id: user._id }, config.REFRESH_TOKEN_SECRET, { expiresIn: config.REFRESH_TOKEN_EXPIRY })

            res.status(200).json(
                {
                    success: true,
                    data: {
                        message: 'User created successfully',
                        accessToken,
                        refreshToken,
                    }
                }
            )
        } catch (error) {

        }
    },
    async loginUser(req, res) {
        try {
            const { email, password } = req.body
            const user = await User.findOne({ email })

            if (!user) {
                return res.status(400).json({ success: false, data: { message: 'No user with provided email' } })
            }

            if (!await bcrypt.compare(password, user.password)) {
                return res.status(400).json({ success: false, data: { message: 'Invalid credentials' } })
            }

            const accessToken = jwt.sign({ id: user._id }, config.ACCESS_TOKEN_SECRET, { expiresIn: config.ACCESS_TOKEN_EXPIRY })
            const refreshToken = jwt.sign({ id: user._id }, config.REFRESH_TOKEN_SECRET, { expiresIn: config.REFRESH_TOKEN_EXPIRY })

            res.status(200).json({ success: true, data: { accessToken, refreshToken } })
        } catch (error) {
            console.error('Error registering user:', error)
            res.status(500).json({ success: false, data: { message: 'Internal server error' } })
        }
    },
    async refreshToken(req, res) {
        const authHeader = req.headers.authorization

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, data: { message: 'Authorization header missing' } })
        }

        const accessToken = authHeader.split(' ')[1]


        jwt.verify(accessToken, config.REFRESH_TOKEN_SECRET, async (error, decodedToken) => {
            if (error) {
                return res.status(400).json({ success: false, data: { message: 'Invalid refresh token' } })
            }

            try {
                const user = await User.findById(decodedToken.id)
                if (!user) {
                    return res.status(400).json({ success: false, data: { message: 'User not found' } })
                }

                const accessToken = jwt.sign({ id: user._id }, config.ACCESS_TOKEN_SECRET, { expiresIn: config.ACCESS_TOKEN_EXPIRY })
                const refreshToken = jwt.sign({ id: user._id }, config.REFRESH_TOKEN_SECRET, { expiresIn: config.REFRESH_TOKEN_EXPIRY })

                res.status(200).json({ success: true, data: { accessToken, refreshToken } })
            } catch (error) {
                console.log('Error retrieving user data:', error)
                return res.status(500).json({ success: false, data: { message: 'Internal server error' } })
            }
        })
    }
}

module.exports = authController
