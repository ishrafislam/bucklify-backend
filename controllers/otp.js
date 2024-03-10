const config = require('../config/config')

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
    }
}

module.exports = otpController
