const express = require('express')
const sqlite3 = require('sqlite3').verbose()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const cors = require('cors')

const app = express()
const db = new sqlite3.Database('./database.db')
const PORT = process.env.PORT || 3000

app.use(express.json())
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:1200', 'https://notepadia.web.app', 'http://192.168.43.2:1200', 'http://192.168.43.2:3000']
}));

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL
)`)


app.post('/register', (req, res) => {
  const { username, password } = req.body

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' })
  }

  const hash = bcrypt.hashSync(password, 10)

  db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hash], (err) => {
    if (err) {
      return res.status(400).json({ message: 'Username already exists' })
    }

    res.status(201).json({ message: 'User registered successfully' })
  })
})

app.post('/login', (req, res) => {
  const { username, password } = req.body

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' })
  }

  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, row) => {
    if (err) {
      return res.status(400).json({ message: 'An error occurred' })
    }

    if (!row || !bcrypt.compareSync(password, row.password)) {
      return res.status(401).json({ message: 'Invalid username or password' })
    }

    const token = jwt.sign({ id: row.id }, 'aeroshin327', { expiresIn: '1h' })
    const date = new Date();
    res.json({ message: `Berhasil login sebagai ${username}`, token, username, date })
  })
})

// Middleware untuk mengotentikasi pengguna
function auth(req, res, next) {
  const token = req.header('Authorization')

  if (!token) {
    return res.status(401).json({ message: 'Access denied' })
  }

  try {
    const decoded = jwt.verify(token, 'aeroshin327')
    req.user = { id: decoded.id }
    next()
  } catch (err) {
    res.status(400).json({ message: 'Invalid token' })
  }
}

// Menambahkan middleware auth ke seluruh route di bawahnya
app.use(auth)

app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`)
})
