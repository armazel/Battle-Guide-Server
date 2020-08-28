const { Router } = require('express');
const User = require('../models/User');
const config = require('config');
const bcrypt = require('bcryptjs');
const { check, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');

const router = Router();

// /api/auth/register
router.post(
    '/register',
    [
        check('email', 'Incorrect email').isEmail(),
        check('password', 'Minimal length of password is 6 simbols').isLength({ min: 6 }),
    ],
     async (req, res) => {
    try{
        const errors = validationResult(req);

        if(!errors.isEmpty()) {
            return res.status(400).json({
                message: "Incorrect data for password or empty password was got",
                error: errors.array(),
            })
        }

        const { email, password } = req.body;
        const candidate = await User.findOne({email});
        if(candidate) {
            return res.status(400).json({ message: 'This user already exists'})
        }
        const hashhedPassword = await bcrypt.hash(password, 12);
        const user = new User({ email, password: hashhedPassword });

        await user.save();

        res.status(201).json({ message: 'New user was created '})
    } catch (e) {
        res.status(500).json({ message: 'someth wrong, please repeat' })
    }
});

// /api/auth/login
router.post(
    '/register',
    [
        check('email', 'Enter the correct email address').normalizeEmail().isEmail(),
        check('password', 'Enter password').exists()
    ],
     async (req, res) => {

    try {
        const errors = validationResult(req);

        if(!errors.isEmpty()) {
            return res.status(400).json({
                message: "Шncorrect data when you log in ",
                error: errors.array(),
            })
        }

        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(500).json({ message: 'smth webkitConvertPointFromNodeToPage, plesase repeat'});
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ message: "Wrong password, please repeat"});
        }

        const token = jwt.sign({
                userId: user.id,
                userName: user.userName
            },
            config.get('jwtSecretKey'),
            { expiresIn: '1h'}
        )

        res.json({
            token,
            userid: user.id
        })
    } catch (e) {
        es.status(500).json({ message: 'someth wrong, please repeat' })
    }
});

module.exports = router;
