import express from 'express';
import mysql from 'mysql';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import cookieParser from 'cookie-parser';

const salt = 2;

const app = express();
app.use(express.json());
app.use(cors({
    origin: ["http://localhost:3000"],
    methods: ["POST", "GET"],
    credentials: true
}));
app.use(cookieParser());

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "007decoded",
    database: 'loginapp'
});

const verifyUser = (req, res, next) => {
    const token = req.cookies.token;

    if (!token) {
        return res.json({ Error: "You are not verified" });
    } else {
        jwt.verify(token, "my-secret-key", (err, decoded) => {
            if (err) {
                return res.json({ Error: "Token not verified" });
            } else {
                req.name = decoded.name;
                next();
            }
        });
    }
}



// Middleware to log IP addresses for all login attempts
app.use((req, res, next) => {
    const ip = req.ip; // Get the IP address of the client

    // Insert the IP address and timestamp into the 'ips' table
    const insertSql = 'INSERT INTO ips (IpAddress, Timestamp) VALUES (?, NOW())';

    db.query(insertSql, [ip], (err, result) => {
        if (err) {
            console.error('Error inserting IP address:', err);
        }
        next();
    });
});

app.get('/', verifyUser, (req, res) => {
    return res.json({ Status: "Success", name: req.name });
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL database');
    // You can start executing queries or perform other database operations here
});

app.post('/Register', (req, res) => {
    const sql = "INSERT INTO login (`name`,`username`,`password`) VALUES(?, ?, ?)";

    bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
        if (err) {
            console.error('Error hashing password:', err);
            return res.status(500).json({ Error: "Error for hashing pwd" });
        }

        const values = [
            req.body.name,
            req.body.email,
            hash
        ];

        console.log('Name:', req.body.name);
        console.log('Email:', req.body.email);
        console.log('Hashed Password:', hash);

        db.query(sql, values, (err, result) => {
            if (err) {
                console.error('Error inserting data:', err);
                return res.status(500).json({ Error: "Inserting data in database" });
            }
            return res.json({ Status: "Success" });
        });
    });
});

app.post('/login', (req, res) => {
    const sql = 'SELECT * FROM login WHERE username = ?;';
    db.query(sql, [req.body.email], (err, data) => {
        if (err) return res.json({ Error: "Logging error in server" });
        if (data.length > 0) {
            bcrypt.compare(req.body.password.toString(), data[0].password, (err, response) => {
                if (err) return res.json({ Error: "Error in comparing password" });
                if (response) {
                    const name = data[0].name;
                    const token = jwt.sign({ name }, "my-secret-key", { expiresIn: '20s' });
                    res.cookie('token', token);
                    return res.json({ Status: "Success" });
                } else {
                    return res.json({ Error: "Password not correct" });
                }
            })
        } else {
            res.json({ Error: "No email existed" });
        }
    })
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    return res.json({ Status: "Success" });
});

app.listen(8081, () => {
    console.log("Server is running on port 8081");
});
