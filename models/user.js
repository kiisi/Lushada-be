const mongoose = require("mongoose")
const bcrypt = require("bcrypt")

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase:true
    },
    password: {
        type: String,
        required: false,
        default: null
    },
    verified_email: {
        type: Boolean,
        default: false
    }
}, {timestamps: true})


userSchema.pre("save", async function(next){

    const salt = await bcrypt.genSalt(12)

    this.password = await bcrypt.hash(this.password, salt)

    next()
})

const userModel = mongoose.model("user", userSchema)

module.exports = userModel