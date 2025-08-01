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
import jwt from 'jsonwebtoken'
import * as client from 'openid-client'

dotenv.config()
process.env.ISSUER_BASE_URL = `https://${process.env.DOMAIN}`

const privateKey = fs.readFileSync(process.env.PRIVATE_KEY_PATH, 'utf8')
const openidIssuerConfig = await client.discovery(new URL(process.env.ISSUER_BASE_URL), process.env.CLIENT_ID, null, client.PrivateKeyJwt(await importPKCS8(privateKey, 'RS256')), { execute: [client.allowInsecureRequests] })

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

app.get('/login', async (req, res) => {
    if (!req.query?.returnTo) {
        return res.status(400).send('Bad request')
    }
    req.session.redirectUri = req.query.returnTo
    try {
        const authorizationUrl = client.buildAuthorizationUrl(openidIssuerConfig,
            {
                redirect_uri: `${process.env.BASE_URL}/callback`,
                scope: `openid profile email offline_access read:current_user_expenses`,
                audience: 'https://acme-fm-backend-api',
                response_type: 'code'
            })
        res.redirect(authorizationUrl)
    } catch (error) {
        console.error('Error during login:', error)
        res.status(500).send('Internal server error')
    }
})

app.get('/callback', express.urlencoded({ extended: true }), async (req, res) => {
    if (!req.query?.code) {
        return res.status(400).send('Bad request')
    }
    try {
        const tokenSet = await client.authorizationCodeGrant(openidIssuerConfig, new URL(`${req.protocol}://${req.get('host')}/${req.originalUrl}`))
        setSessionTokens(req.session, tokenSet)
        res.redirect(req.session.redirectUri)
    } catch (error) {
        console.error('Error during callback:', error)
        res.status(500).send('Internal server error')
    }
})

app.get('/logout', async (req, res) => {
    if (req.session.idToken) {
        const redirectUri = client.buildEndSessionUrl(openidIssuerConfig, {
            post_logout_redirect_uri: new URL(process.env.BASE_URL),
            id_token_hint: req.session.idToken
        })
        setSessionTokens(req.session, null)
        res.redirect(redirectUri.toString())
    } else {
        res.redirect(process.env.BASE_URL)
    }
})

// Landing page - show totals if the user is authenticated
app.get("/", async (req, res) => {
    let locals = {
        path: req.path,
        user: req.session.user,
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
        user: req.session.user,
        expenses: null
    }
    try {
        if (locals.user) {
            const apiUrl = `${process.env.BACKEND_URL}/expenses`
            const response = await fetchProtectedResource(req.session, apiUrl)
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
        user: req.session.user,
        idToken: req.session.idToken,
        accessToken: req.session.accessToken?.access_token,
        refreshToken: req.session.refreshToken
    }
    res.render('tokens', locals)
})

// Show userinfo, requires authorization
app.get("/userinfo", async (req, res) => {
    const locals = {
        path: req.path,
        user: req.session.user,
        userinfo: null
    }
    try {
        if (locals.user) {
            const apiUrl = `${process.env.ISSUER_BASE_URL}/userinfo`
            const response = await fetchProtectedResource(req.session, apiUrl)
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

// Check and refresh the cached tokens if necessary before use
async function checkAndRefreshTokens(session) {
    if (session && session.idToken && session.accessToken?.access_token && session.refreshToken) {
        try {
            const decoded = jwt.decode(session.accessToken.access_token, { complete: true })
            if (Date.now() / 1000 >= decoded.payload.exp) {
                // Force a token refresh if the current token is expired (all tokens).
                const tokenSet = await client.refreshTokenGrant(openidIissuerConfig, session.refreshToken)
                setSessionTokens(session, tokenSet)
            }
        } catch (error) {
            setSessionTokens(session, null)
            console.error('Error checking and refreshing tokens:', error)
            throw new Error('Failed to refresh tokens')
        }
    }
}

// fetchProtectResource supports DPoP
async function fetchProtectedResource(req, url, method = 'GET', body, headers) {
    await checkAndRefreshTokens(req.session)
    if (!req.session || !req.session.idToken || !req.session.accessToken?.access_token || !req.session.refreshToken) {
        throw new Error('Unauthorized access - no valid tokens found')
    }
    // Insecure URLs are enabled for the issuer configuration only for testing on localhost;
    // A guard against insecure URLs must be enforced for the rest of the network here.
    if (!/^(http:\/\/localhost[\/:])|(^https:)/.test(url)) {
        throw new Error('Invalid URL - must start with http://localhost or https://')
    }
    try {
        const accessToken = req.session.accessToken.access_token
        const response = await client.fetchProtectedResource(openidIssuerConfig, accessToken, new URL(url), method, body, headers)
        return response
    } catch (error) {
        console.error('Error fetching protected resource:', error)
        throw new Error('Failed to fetch protected resource')
    }
}