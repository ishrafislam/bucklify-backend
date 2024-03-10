const bcrypt = require('bcryptjs')

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
    }
}

module.exports = userController
