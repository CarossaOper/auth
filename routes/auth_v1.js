const express = require("express")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const crypto = require("crypto")
const mongoose = require("mongoose")

const AuthSchema = require("../schemas/authschema.js")
const Auths = mongoose.model("Auths", AuthSchema)
const TokenSchema = require("../schemas/tokenschema.js")
const Tokens = mongoose.model("Tokens", TokenSchema)

const router = express.Router()
router.use(express.json())

//const tokenSecret = crypto.randomBytes(64).toString("hex")
const tokenSecret = "b539526ecec5d6863e4bcddddfb3c7caffc59f245e506832600233cdea1694578e7d5ece682bdb8917dff8d4e27f523dccb359900b56a1aceb4e234b78d0fee2"
//const refreshToken = crypto.randomBytes(64).toString("hex")
const refreshToken = "056a765d5fd47b5b5d2ccefc0172c508f85e5e843be291a93aee9237432b1d074c10d7823a2133346db630d4d644238227ac7c16eb61c24c573f25a7ca08dc16"

process.env.TOKENSECRET = tokenSecret
console.log(tokenSecret)
process.env.REFRESHTOKEN = refreshToken
console.log(refreshToken)

// DISABLE THIS ROUTE IN DEPOLYMENT
router.post("/register", async (req, res) => {
    console.log(`Registration: ${process.env.ENABLE_REGISTER}`)

    if (process.env.ENABLE_REGISTER) {
        Auths.findOne({ user: req.body.user }, async (error, result) => {
            if (error) {
                res.status(503).json({error: error})
            } else {
                if (result === null) {
                    // no user existing user could be found
                    try {
                        let hashedpw = await bcrypt.hash(req.body.password, 10)
                
                        let user = new Auths({
                            user: req.body.user,
                            password: hashedpw,
                            privilege: 0
                        })
                        
                        // store user in database
                        user.save((err) => {
                            if (err) {
                                res.status(504).json({error: err})
                            }
                        })
            
                        res.status(201).send()
                    } catch {
                        res.status(500).send()
                    }
                } else {
                    res.status(401).send("Username taken")
                }
            }
        })
    } else {
        res.sendStatus(403)
    }
})

router.post("/login", async (req, res) => {
    Auths.findOne({ user: req.body.user }, async (error, result) => {

        if (error) {
            res.status(503).json({error: error})
        } else {
            if (result === null) {
                // no user existing user could be found
                res.status(400).send("Unable to find user")
            } else {
                // user exists
                try {
                    if (await bcrypt.compare(req.body.password, result.password)) {
                        // Successful Login
                        let token = genAccessToken({user: result.user, privilege: result.privilege})
                        let refresh = jwt.sign({user: result.user, privilege: result.privilege}, process.env.REFRESHTOKEN)

                        let tokensav = new Tokens({
                            refreshtoken: refresh
                        })

                        tokensav.save((err) => {
                            if (err) {
                                res.status(504).json({error: err})
                            }
                        })

                        res.status(201).send({token: token, refresh: refresh})
                    } else {
                        res.status(401).send("Invalid Password")
                    }
                } catch {
                    res.status(500).send()
                }
            }
        }
    })
})

router.delete("/logout", (req, res) => {
    Tokens.findOneAndDelete({ refreshtoken: req.body.token }, (error, result) => {
        if (error) {
            res.status(503).json({error: error})
        } else {
            res.sendStatus(204)
        }
    })
})

// use refreshtoken to generate new token after expiration
router.post("/token", (req, res) => {
    let refresh = req.body.refresh
    if (refresh === undefined) return res.sendStatus(401)
    
    Tokens.findOne({ refreshtoken: refresh }, (error, result) => {
        if (error) {
            res.status(503).json({error: error})
        } else {

            if (result === null) {
                res.sendStatus(403)
            } else {
                jwt.verify(refresh, process.env.REFRESHTOKEN, (err, data) => {
                    // generate new accesstoken if we have a valid refreshtoken
                    if (err) return res.sendStatus(403)
                    let token = genAccessToken({user: data.user, privilege: data.privilege})
                    res.json(token)
                })
            }
        }
    })
})

function genAccessToken(data) {
    return jwt.sign(data, tokenSecret, { expiresIn: "10m"})
}

module.exports = router
