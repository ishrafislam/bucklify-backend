const config = {
    PORT: process.env.PORT || 3000,
    ACCESS_TOKEN_SECRET: process.env.ACCESS_TOKEN_SECRET,
    ACCESS_TOKEN_EXPIRY: process.env.ACCESS_TOKEN_EXPIRY,
    REFRESH_TOKEN_SECRET: process.env.REFRESH_TOKEN_SECRET,
    REFRESH_TOKEN_EXPIRY: process.env.REFRESH_TOKEN_EXPIRY,
    MONGODB_URI: process.env.MONGODB_URI,
    MAIL_USER: process.env.MAIL_USER,
    MAIL_PASSWORD: process.env.MAIL_PASSWORD,
    REGISTER_OTP_LEN: process.env.REGISTER_OTP_LEN,
    LOGIN_OTP_LEN: process.env.LOGIN_OTP_LEN,
}

module.exports = config
