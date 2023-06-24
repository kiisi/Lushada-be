const router = require("express").Router()
const authController = require("../controllers/auth")

/*
 * @route POST /auth/signup
 * @access public
 * @body {string} email
 * @body {string} password
 * @returns {object} 
*/

router.post("/signup", authController.signup)

/*
 * @route POST /auth/signup
 * @access public
 * @body {string} email
 * @body {string} password
 * @returns {object}
*/

router.post("/login", authController.login)

/*
 * @route GET /auth/verify-user
 * @access public 
*/

router.get("/verify-user", authController.verifyUser)

/*
 * @route GET /auth/logout
 * @access public
*/

router.get("/logout", authController.logout)

module.exports = router