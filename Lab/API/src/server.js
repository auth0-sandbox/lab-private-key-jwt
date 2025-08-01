// API: server.js
// Lab: API Access Management
//


import cors from 'cors'
import dotenv from "dotenv"
import express from 'express'
import logger from 'morgan'
import path, { dirname, normalize } from 'path'
import { fileURLToPath } from 'url'
import { auth, requiredScopes } from 'express-oauth2-jwt-bearer'

dotenv.config()

if (!process.env.BASE_URL) {
    process.env.BASE_URL = !process.env.CODESPACE_NAME
        ? `http://localhost:${process.env.PORT}`
        : `https://${process.env.CODESPACE_NAME}-${process.env.PORT}.${process.env.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}`
}

const app = express()

const __filename = fileURLToPath(import.meta.url)
const __fileDirectory = dirname(__filename)
const __dirname = normalize(path.join(__fileDirectory, ".."))
app.set("views", path.join(__dirname, "views"))
app.set("view engine", "pug")

app.use(logger("combined"))

app.use(cors({ origin: '*', methods: 'ET', preflightContinue: false, optionsSuccessStatus: 204 }))

app.use(express.static(path.join(__dirname, "public")))

app.get('/', (req, res) => {
    res.render("home", { })
})

// This middleware requires authorization for any middleware registered after it.
app.use(auth({
    audience: process.env.AUDIENCE,
    issuer: process.env.ISSUER_BASE_URL,
    jwksUri: process.env.JWKS_URI,
    tokenSigningAlg: process.env.TOKEN_SIGNING_ALG || 'RS256'
}))

// This returns the expenses for the current user; This is a mock; in a real application we would
// use req.auth.payload.sub to get retrieve the data by the current user ID.
// app.get('/expenses', requiredScopes('read:current_user_expenses'), (req, res) => {
app.get('/expenses', (req, res) => {
    res.json(expenses)
})

// Alternative form: if the user can read all user expenses return data for userid; if the user
// can read their own expenses return data if the user ID matches the access token subject claim,
// otherwise return a 403 Forbidden error.
app.get('/expenses/:userid', (req, res) => {
    if (req.auth
        && (req.auth.payload.scope.includes('read:user_expenses')
        || (req.auth.payload.sub === req.params.userid
        && !req.auth.payload.scope.includes('read:current_user_expenses')))) {
            res.json(expenses)
    } else {
        res.status(401).json({ status: 401, message: 'Unauthorized' })
    }
})

app.use((err, req, res, next) => {
    res.status(err.status || 500)
    res.json({ status: err.status, message: err.message })
})

app.listen(process.env.PORT, () => console.log(`Backend API started, use ctrl/cmd-click to follow this link: ${process.env.BASE_URL}`))

const expenses = [
    {
        date: new Date(),
        description: 'Pizza for a Coding Dojo session.',
        value: 102,
    },
    {
        date: new Date(),
        description: 'Coffee for a Coding Dojo session.',
        value: 42,
    },
]