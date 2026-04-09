import bcrypt from 'bcryptjs';
import 'dotenv/config';
import jwt from 'jsonwebtoken';
import mysql from 'mysql2/promise';

const SECRET_KEY = process.env.JWT_SECRET;

export const pool = mysql.createPool({
    host: process.env.DB_HOST || '127.0.0.1',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DATABASE || 'sniffer_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

export const getUsers = async () => {
    try {
        const [rows] = await pool.query('SELECT * FROM users');
        return rows;
    } catch { return []; }
};

export const createUser = async (username, password) => {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashedPassword, 'user']);
};

export const verifyToken = (req, res, next) => {
    const token = req.cookies?.token;

    if (!token) {
        return res.status(401).json({ message: "กรุณาเข้าสู่ระบบ" });
    }
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        console.log(req.user);
        next();
    } catch (err) {
        return res.status(403).json({ message: "Token ไม่ถูกต้องหรือหมดอายุ" });
    }
};