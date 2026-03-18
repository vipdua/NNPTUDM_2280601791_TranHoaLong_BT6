var express = require("express");
var router = express.Router();
let userController = require('../controllers/users')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let fs = require('fs');
const { CheckLogin } = require("../utils/authHandler");

const privateKey = fs.readFileSync('./keys/private.key', 'utf8');

router.post('/register', async function (req, res, next) {
    try {
        let { username, password, email } = req.body;
        let newUser = await userController.CreateAnUser(
            username, password, email, "69b0ddec842e41e8160132b8"
        )
        res.send(newUser)
    } catch (error) {
        res.status(404).send(error.message)
    }
})

router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let user = await userController.GetAnUserByUsername(username);

        if (!user) {
            return res.status(404).send({
                message: "thong tin dang nhap sai"
            });
        }

        if (user.lockTime > Date.now()) {
            return res.status(404).send({
                message: "ban dang bi ban"
            });
        }

        if (bcrypt.compareSync(password, user.password)) {

            user.loginCount = 0;

            await user.save();

            let token = jwt.sign(
                { id: user._id },
                privateKey,
                {
                    algorithm: 'RS256',
                    expiresIn: '1h'
                }
            );

            return res.send(token);

        } else {
            user.loginCount++;

            if (user.loginCount == 3) {
                user.loginCount = 0;
                user.lockTime = Date.now() + 3600 * 1000;
            }

            await user.save();

            return res.status(404).send({
                message: "thong tin dang nhap sai"
            });
        }

    } catch (error) {
        res.status(404).send({
            message: error.message
        })
    }
})

router.post('/change-password', CheckLogin, async function (req, res) {
    try {
        let { oldPassword, newPassword } = req.body;

        let user = req.user;

        let isMatch = bcrypt.compareSync(oldPassword, user.password);
        if (!isMatch) {
            return res.status(400).send({
                message: "mat khau cu khong dung"
            });
        }

        if (!newPassword || newPassword.length < 8) {
            return res.status(400).send({
                message: "mat khau moi phai >= 8 ky tu"
            });
        }

        user.password = newPassword;
        await user.save();

        res.send({
            message: "doi mat khau thanh cong"
        });

    } catch (error) {
        res.status(500).send({
            message: error.message
        });
    }
});

router.get('/me', CheckLogin, function (req, res, next) {
    res.send(req.user)
})

module.exports = router;