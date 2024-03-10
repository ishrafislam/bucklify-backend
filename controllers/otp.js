const config = require('../config/config')
const OTP = require('../models/otp')

const otpController = {
    generate(charset, otpLength) {
        let otp = ''
        for (let i = 0; i < otpLength; i++) {
            const randomIndex = Math.floor(Math.random() * charset.length)
            otp += charset[randomIndex]
        }
        return otp
    },
    generateOtp(forRegister = false) {
        return this.generate(
            '0123456789',
            forRegister ? config.REGISTER_OTP_LEN : config.LOGIN_OTP_LEN
        )
    },
    generateRef() {
        return this.generate(
            '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            10
        )
    },
    createOtp(user) {
        let dateTime = new Date()
        dateTime.setMinutes(dateTime.getMinutes() + 5)

        const otp = new OTP({
            userId: user._id,
            value: this.generateOtp(true),
            referenceId: this.generateRef(),
            expireAt: dateTime.toISOString(),
        })

        otp.save()
        return otp
    }
}

module.exports = otpController
