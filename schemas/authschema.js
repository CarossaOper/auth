const mongoose = require("mongoose")

const AuthSchema = new mongoose.Schema({
    user: String,
    password: String,
    privilege: Number,
})

module.exports = AuthSchema