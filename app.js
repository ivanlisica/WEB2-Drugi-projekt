const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');

const app = express();
const port = 3000;

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

const db = new sqlite3.Database(':memory:');

db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, xssProtection INTEGER, secureStorage INTEGER)");
});

function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
app.get('/', (req, res) => {
  res.render('index');
});



app.post('/register', (req, res) => {
    let { username, password, xssProtection, secureStorage } = req.body;
  
    if (secureStorage === 'on') {
        password = hashPassword(password);
    }

    if (xssProtection === 'on') {
        username = escapeHtml(username);
    }

    db.run('INSERT INTO users (username, password, xssProtection, secureStorage) VALUES (?, ?, ?, ?)',
        [username, password,xssProtection === 'on' ? 1 : 0, secureStorage === 'on' ? 1 : 0],
        (err) => {
            if (err) {
                console.error(err);
                res.status(500).send('Error registering user');
            } else {
                res.redirect('/users');
            }
        }
    );
});
app.get('/users', (req, res) => {
  db.all("SELECT * FROM users", (err, rows) => {
      res.render('users', { users: rows, escapeHtml: escapeHtml });
  });
});

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

app.listen(port, () => {
    console.log(`App running at http://localhost:${port}`);
});
