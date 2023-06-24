const jwt = require("jsonwebtoken");
const { createTransport } = require("nodemailer");

// Create JWT Token

const createJWT = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET_KEY, {
        expiresIn: 24 * 60 * 60
    })
}

module.exports = {
    createJWT
}