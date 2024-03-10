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
            let user = await User.findOne({ email })

            if (user && user.verified) {
                return res.status(400).json({ success: false, data: { message: 'User exists for the provided email' } })
            }

            if (!user) {
                user = new User({
                    firstName,
                    lastName,
                    email,
                    password: await bcrypt.hash(password, 5),
                    verified: false,
                    twoFAEnabled: false,
                })

                user.save()
            }

            let dateTime = new Date()
            dateTime.setMinutes(dateTime.getMinutes() + 5)

            const otp = new OTP({
                userId: user._id,
                value: otpController.generateOtp(true),
                referenceId: otpController.generateRef(),
                expireAt: dateTime.toISOString(),
            })

            otp.save()

            mailController.sendMail(user.email, 'Email verification', `Your verification code is ${otp.value}`)

            res.status(200).json(
                {
                    success: true,
                    data: {
                        message: 'OTP sent to your email',
                        otpReference: otp.referenceId,
                        expireAt: otp.expireAt,
                    }
                }
            )
        } catch (error) {
            console.error('Error while registering user:', error)
            res.status(500).json({ success: false, data: { message: 'Internal server error' } })
        }
    },
    async confirmRegister(req, res) {
        try {
            const { referenceId, otpValue } = req.body
            const otp = await OTP.findOne({ referenceId })

            if (!otp) {
                return res.status(400).json({ success: false, data: { message: 'OTP not found by provided reference ID' } })
            }

            const currentDateTime = new Date()
            const otpExpireTime = new Date(otp.expireAt)

            if (currentDateTime >= otpExpireTime) {
                return res.status(400).json({ success: false, data: { message: 'OTP expired' } })
            }

            if (otp.value != otpValue) {
                return res.status(400).json({ success: false, data: { message: 'Wrong OTP provided' } })
            }

            const user = await User.findById(otp.userId)
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
            console.error('Error while verifying user registration:', error)
            res.status(500).json({ success: false, data: { message: 'Internal server error' } })
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

            if (!user.verified) {
                let dateTime = new Date()
                dateTime.setMinutes(dateTime.getMinutes() + 5)

                const otp = new OTP({
                    userId: user._id,
                    value: otpController.generateOtp(true),
                    referenceId: otpController.generateRef(),
                    expireAt: dateTime.toISOString(),
                })

                otp.save()

                mailController.sendMail(user.email, 'Email verification', `Your verification code is ${otp.value}`)

                return res.status(400).json(
                    {
                        success: true,
                        data: {
                            message: 'OTP sent to your email',
                            otpReference: otp.referenceId,
                            expireAt: otp.expireAt,
                        }
                    }
                )
            }

            const accessToken = jwt.sign({ id: user._id }, config.ACCESS_TOKEN_SECRET, { expiresIn: config.ACCESS_TOKEN_EXPIRY })
            const refreshToken = jwt.sign({ id: user._id }, config.REFRESH_TOKEN_SECRET, { expiresIn: config.REFRESH_TOKEN_EXPIRY })

            res.status(200).json({ success: true, data: { accessToken, refreshToken } })
        } catch (error) {
            console.error('Error while logging user in:', error)
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
                console.log('Error while refreshing token:', error)
                return res.status(500).json({ success: false, data: { message: 'Internal server error' } })
            }
        })
    }
}

module.exports = authController
