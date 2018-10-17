const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const config = require('../config');

const VerifyToken = require('./VerifyToken');

const express = require('express');
const router = express.Router();

router.use(express.urlencoded({ extended: false }));
router.use(express.json());

const User = require('../user/User');

/*
router.get('/me', (req, res) => {
    const token = req.headers['x-access-token'];

    if (!token) return res.status(401).send({ auth: false, message: 'No token provided.' });

    jwt.verify(token, config.secret, function(err, decoded) { 
        if (err) return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });

        // sends the decoded jwt
        // res.status(200).send(decoded);

        User.findById(decoded.id, { password: 0 }, (err, user) => {
            if (err) return res.status(500).send("There was a problem finding the user.");

            if (!user) return res.status(404).send("No user found.");

            res.status(200).send(user);
        });
    });
});
*/

router.get('/me', VerifyToken, function(req, res, next) {
    User.findById(req.userId, { password: 0 }, function (err, user) {
        if (err) return res.status(500).send({
            error: true,
            message: 'There was a problem finding the user.'
        });

        if (!user) return res.status(404).send({
            error: true,
            message: 'No user found.'
        });

        res.status(200).send(user);
    });
});

router.post('/register', (req, res) => {
    const hashedPassword = bcrypt.hashSync(req.body.password, 8);

    User.create({
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword
    },
    function (err, user) {
        if (err) return res.status(500).send('There was a problem registering the user.');

        var token = jwt.sign({ id: user._id }, config.secret, {
            expiresIn: 60 * 60 //expires in 1hr
        });

        res.status(200).send({ auth: true, token });
    });
});


router.post('/login', (req, res) => {

    User.findOne({ email: req.body.email }, (err, user) => {
        if (err) return res.status(500).send('Error on the server.');
        if (!user) return res.status(404).send('No user found.');

        const passwordIsValid = bcrypt.compareSync(req.body.password, user.password);

        if (!passwordIsValid) return res.status(401).send({ auth: false, token: null });

        const token = jwt.sign({ id: user._id }, config.secret, {
            expiresIn: 60 * 60 //expires in 1hr
        });

        res.status(200).send({ auth: true, token: token });
    });
});

module.exports = router;