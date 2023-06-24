const UserModel = require("../models/user")
const validator = require('validator');
const bcrypt = require("bcrypt")
const { createJWT } = require("../helpers/index")
const jwt = require("jsonwebtoken");


const signup = async (request, response) => {

    try {

        const { name, email, password, confirm_password } = request.body

        if (!name || !email || !password || !confirm_password) {
            return response.status(403).json({ error: "Incomplete credentials!" })
        }

        if (!validator.isEmail(email)) {
            return response.status(403).json({ error: "Invalid email!" })
        }

        if (confirm_password !== password) {
            return response.status(403).json({ error: "Password does not match!" })
        }

        const email_existence = UserModel.findOne({ email: email })

        if (!email_existence) {
            return response.status(403).json({ error: "Email already exists!" })
        }

        await UserModel.create({ name, email, password })

        return response.status(201).json({ success: "Account created" })

    } catch (err) {
        console.log("Error:", err)
        return response.status(201).json({ error: "Unexpected error occurred!" })
    }

}

const login = async (request, response) => {

    try {

        const { email, password } = request.body

        if (!email || !password) {
            return response.status(403).json({ error: "Incomplete credentials!" })
        }

        if (!validator.isEmail(email)) {
            return response.status(403).json({ error: "Invalid email!" })
        }

        const user_account = await UserModel.findOne({ email: email }).exec()

        console.log(user_account)

        if (!user_account) {
            return response.status(403).json({ error: "Account not found!" })
        }

        let compare_password = await bcrypt.compare(password, user_account.password)

        user_account.password = undefined

        if (!compare_password) {
            return response.status(403).json({ error: "Account not found!" })
        }

        const _tk = createJWT(user_account._id)

        response.cookie('jwt', _tk, {
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: true,
            secure: true,
            sameSite: 'none',
        })

        return response.status(200).json({ success: "Login successful", payload: user_account })

    } catch (err) {
        console.log("Error:", err)
        return response.status(201).json({ error: "Unexpected error occurred!" })
    }
}

const verifyUser = (request, response) => {
    try {
        const token = request.cookies['jwt']
        if (token) {
            jwt.verify(token, process.env.JWT_SECRET_KEY, async (err, decodedToken) => {
                if (err) {
                    console.log(err)
                    response.status(200).json({ error: "Unauthorized" })
                } else {
                    let user = await UserModel.findById(decodedToken.id);
                    if (user) {
                        user.password = undefined
                        return response.status(200).json({ success: 'Authorized', payload: user })
                    } else {

                        return response.status(200).json({ error: 'Unauthorized' })
                    }
                }
            })
        } else {
            return response.status(200).json({ error: "Unauthorized" })
        }
    } catch (err) {
        console.log(err)
    }
}


const logout = (request, response) => {
    response.cookie('jwt', ' ', {
        maxAge: 1,
        httpOnly: true,
        secure: true,
        sameSite: 'none',
    })
    response.status(200).json({ success: true })
}

module.exports = {
    signup,
    login,
    verifyUser,
    logout
}