const mongoose = require("mongoose")

const TokenSchema = new mongoose.Schema({
    refreshtoken: String
})

module.exports = TokenSchema