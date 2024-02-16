const userController = {
    async userInfo(req, res) {
        res.status(200).json(
            {
                success: true,
                data: {
                    first_name: req.user.firstName,
                    last_name: req.user.lastName,
                    email: req.user.email
                }
            }
        )
    }
}

module.exports = userController
