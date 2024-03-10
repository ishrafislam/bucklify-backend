const bcrypt = require('bcryptjs')
const mailController = require('./mail')
const otpController = require('./otp')
const OTP = require('../models/otp')

const userController = {
    async userInfo(req, res) {
        res.status(200).json(
            {
                success: true,
                data: {
                    first_name: req.user.firstName,
                    last_name: req.user.lastName,
                    email: req.user.email,
                    emailVerified: req.user.verified,
                    twoFAEnabled: req.user.twoFAEnabled,
                }
            }
        )
    },
    async resetPassword(req, res) {
        try {
            const { old_password, new_password } = req.body

            if (!await bcrypt.compare(old_password, req.user.password)) {
                return res.status(400).json({ success: false, data: { message: 'Invalid credentials' } })
            }

            if (old_password == new_password) {
                return res.status(400).json({ success: false, data: { message: 'New password can\'t be same as old password' } })
            }

            req.user.password = await bcrypt.hash(new_password, 5)
            req.user.save()

            res.status(200).json({ success: true, data: { message: 'Updated the password successfully' } })
        } catch (error) {
            console.error('Error updating password of user:', error)
            res.status(500).json({ success: false, data: { message: 'Internal server error' } })
        }
    },
    async update2FARequest(req, res) {
        try {
            const { status } = req.body

            if (req.user.twoFAEnabled == status) {
                return res.status(400).json({ success: false, data: { message: '2FA status already same as requested' } })
            }

            if (status) {
                otp = otpController.createOtp(req.user)
                mailController.sendMail(req.user.email, "Enable 2FA", `Your verification code is ${otp.value}`)

                return res.status(200).json(
                    {
                        status: true,
                        data: {
                            message: 'OTP sent to your email',
                            otpReference: otp.referenceId,
                            expireAt: otp.expireAt,
                        }
                    }
                )
            }

            req.user.twoFAEnabled = false
            req.user.save()

            res.status(200).json({ status: true, data: { message: '2FA disabled successfully' } })
        } catch (error) {
            console.error('Error updating password of user:', error)
            res.status(500).json({ success: false, data: { message: 'Internal server error' } })
        }
    },
    async update2FAVerify(req, res) {
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

            req.user.twoFAEnabled = true
            req.user.save()

            res.status(200).json({ status: true, data: { message: '2FA enabled successfully' } })
        } catch (error) {
            console.error('Error updating password of user:', error)
            res.status(500).json({ success: false, data: { message: 'Internal server error' } })
        }
    }
}

module.exports = userController
