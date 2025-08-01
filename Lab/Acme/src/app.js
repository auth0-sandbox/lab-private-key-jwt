// Acme: app.js
// Lab: API Access Management
//

import cookieParser from 'cookie-parser'
import dotenv from 'dotenv'
import express from 'express'
import session from 'express-session'
import fs from 'fs'
import createError from 'http-errors'
import logger from 'morgan'
import path, { dirname, normalize } from 'path'
import { fileURLToPath } from 'url'
import { importPKCS8 } from 'jose'

dotenv.config()
process.env.ISSUER_BASE_URL = `https://${process.env.DOMAIN}`

if (!process.env.BASE_URL) {
    process.env.BASE_URL = !process.env.CODESPACE_NAME
        ? `http://localhost:${process.env.PORT}`
        : `https://${process.env.CODESPACE_NAME}-${process.env.PORT}.${process.env.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}`
}

// Create Express
const app = express()

// Assuming this file is in the src directory, find the project directory
const __filename = fileURLToPath(import.meta.url)
const __fileDirectory = dirname(__filename)
const __dirname = normalize(path.join(__fileDirectory, ".."))
app.set("views", path.join(__dirname, "views"))
app.set("view engine", "pug")

app.use(logger("combined"))

// Accept both JSON and URL-encoded bodies, and parse cookies
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())

// Serve the static files in the public directory
app.use(express.static(path.join(__dirname, "public")))

// Use sessions
app.use(
    session({
        secret: process.env.SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: false,
            sameSite: 'lax',
            secure: false
        }
    })
)

// Set up the middleware for the route paths

app.get("/login", (req, res) => {
    res.oidc.login({
        returnTo: req.query.returnTo || "/"
    })
})

// Landing page - show totals if the user is authenticated
app.get("/", async (req, res) => {
    let locals = {
        path: req.path,
        user: req.oidc?.user,
        total: null,
        count: null
    }
    try {
        if (locals.user) {
            const apiUrl = `${process.env.BACKEND_URL}/expenses`
            const response = await fetchProtectedResource(req, apiUrl)
            const expenses = await response.json()
            locals.total = expenses.reduce((accum, expense) => accum + expense.value, 0)
            locals.count = expenses.length
        }
    } catch (error) {
        console.error(error)
    }
    res.render('home', locals)
})

// Show expenses, requires authentication
app.get("/expenses", async (req, res) => {
    let locals = {
        path: req.path,
        user: req.oidc?.user,
        expenses: null
    }
    try {
        if (locals.user) {
            const apiUrl = `${process.env.BACKEND_URL}/expenses`
            const response = await fetchProtectedResource(req, apiUrl)
            const expenses = await response.json()
            locals.expenses = expenses
        }
    } catch (error) {
        console.error(error)
    }
    res.render('expenses', locals)
})

// Show public key and download
app.get("/publickey", async (req, res) => {
    let publicKey = null
    try {
        publicKey = fs.readFileSync(process.env.PUBLIC_KEY_PATH, 'utf8')
    } catch (error) {
        console.error('Error reading public key:', error)
    }
    res.render('publickey', { path: req.path, user: req.session.user, publicKey: publicKey })
})

app.get('/publickey.pem', (req, res) => {
    try {
        const publicKey = fs.readFileSync(process.env.PUBLIC_KEY_PATH, 'utf8')
        res.setHeader('Content-Type', 'application/x-pem-file')
        res.send(publicKey)
    } catch (error) {
        res.status(404).send('Public key not found')
    }
})

// Show tokens, requires authorization
app.get("/tokens", async (req, res) => {
    const locals = {
        path: req.path,
        user: req.oidc?.user,
        idToken: req.oidc?.idToken,
        accessToken: req.oidc?.accessToken?.access_token,
        refreshToken: req.oidc?.refreshToken
    }
    res.render('tokens', locals)
})

// Show userinfo, requires authorization
app.get("/userinfo", async (req, res) => {
    const locals = {
        path: req.path,
        user: req.oidc?.user,
        userinfo: null
    }
    try {
        if (locals.user) {
            const apiUrl = `${process.env.ISSUER_BASE_URL}/userinfo`
            const response = await fetchProtectedResource(req, apiUrl)
            locals.userinfo = await response.json()
        }
    } catch (error) {
        console.error(error)
    }
    res.render('userinfo', locals)
})

// Catch 404 and forward to error handler
app.use((req, res, next) => next(createError(404)))

// Error handler
app.use((err, req, res, next) => {
    res.locals.message = err.message
    res.locals.error = err
    res.status(err.status || 500)
    res.render("error", {
        user: req.session.user,
    })
})

app.listen(process.env.PORT, () => {
    console.log(`WEB APP: ${process.env.BASE_URL}`)
})

// Set session tokens
function setSessionTokens(session, tokenSet) {
    if (tokenSet) {
        req.session.user = jwt.decode(tokenSet.id_token, { complete: true }).payload
        req.session.idToken = tokenSet.id_token
        const decodedAccessToken = jwt.decode(tokenSet.access_token, { complete: true })
        req.session.accessToken = {
            access_token: tokenSet.access_token,
            expires_at: decodedAccessToken.payload.exp,
            token_type: tokenSet.token_type,
            scope: decodedAccessToken.payload.scope
        }
        req.session.refreshToken = tokenSet.refresh_token
    } else {
        delete req.session.user
        delete req.session.idToken
        delete req.session.accessToken
        delete req.session.refreshToken
    }
}

// Set up the fetch call to the API with the bearer token
async function fetchProtectedResource(req, url, method, body, headers) {
    if (!req.oidc || !req.oidc.accessToken) {
        throw new Error("User does not have an access token");
    }
    const options = {
        method: method || "GET",
        body: body ? JSON.stringify(body) : null,
        headers: new Headers({
            "Content-Type": "application/json",
            Accept: "application/json",
            Authorization: `Bearer ${req.oidc.accessToken.access_token}`,
            ...headers,
        }),
    }
    const response = await fetch(url, options);
    if (!response.ok) {
        throw new Error(`Error from fetch: ${response.statusText}`)
    }
    return response;
}