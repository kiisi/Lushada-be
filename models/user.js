const mongoose = require("mongoose")
const bcrypt = require("bcrypt")

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim:true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase:true,
        trim:true
    },
    password: {
        type: String,
        required:true
    },
    gender: {
        type: String,
        toLowerCase: true,
        enum: ["male", "female"],
        trim: true,
        required:true
    },
}, {timestamps: true})


userSchema.pre("save", async function(next){

    const salt = await bcrypt.genSalt(12)

    this.password = await bcrypt.hash(this.password, salt)

    next()
})

const userModel = mongoose.model("user", userSchema)

module.exports = userModel