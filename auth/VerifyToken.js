const jwt = require('jsonwebtoken');
const config = require('../config');

function verifyToken(req, res, next) {
    const token = req.headers['x-access-token'];

    if(!token) {
        return res.status(403).send({
            auth: false,
            message: 'No token provided.'
        });
    }

    jwt.verify(token, config.secret, function(err, decoded) {
        if (err) {
            return res.status(500).send({
                auth: false,
                message: 'Failed to authticate token.'
            });
        }

        //if token is authenticated, save the user's id for use later
        req.authorized = true;
        req.userId = decoded.id;
        next();
    });
}

module.exports = verifyToken;