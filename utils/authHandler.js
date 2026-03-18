let userController = require('../controllers/users')
let jwt = require('jsonwebtoken')
const fs = require('fs');
const publicKey = fs.readFileSync('./keys/public.key', 'utf8');

module.exports = {
    CheckLogin: async function (req, res, next) {
        try {
            if (!req.headers.authorization || !req.headers.authorization.startsWith("Bearer")) {
                return res.status(404).send({
                    message: "ban chua dang nhap"
                });
            }

            let token = req.headers.authorization.split(" ")[1];

            let result = jwt.verify(token, publicKey, {
                algorithms: ['RS256']
            });

            if (result.exp * 1000 < Date.now()) {
                return res.status(404).send({
                    message: "ban chua dang nhap"
                });
            }

            let user = await userController.GetAnUserById(result.id);

            if (!user) {
                return res.status(404).send({
                    message: "ban chua dang nhap"
                });
            }

            req.user = user;
            next();

        } catch (error) {
            return res.status(404).send({
                message: "ban chua dang nhap"
            });
        }
    }
}