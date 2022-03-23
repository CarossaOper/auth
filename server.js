const express = require("express")
const mongoose = require("mongoose")
const cors = require('cors')
const router = require("./routes/auth_v1.js")

const app = express()
const port = process.env.PORT

app.use(cors())
app.use("/auth", router)

mongoose.connect(process.env.DB_URL, {useNewUrlParser: true, useUnifiedTopology: true});
const db = mongoose.connection;

db.on("error", console.error.bind(console, "Error running Mongoose:"));

app.listen(port)
console.log(`Started authentication server on port ${port}`)