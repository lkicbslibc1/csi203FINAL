// ไฟล์นี้ต้องเปลี่ยนจาก json ไปเป็น mysql
import fs from 'fs/promises';
import path from 'path';
import bcrypt from 'bcryptjs';
import 'dotenv/config'; 
import jwt from 'jsonwebtoken'
/////// authorizationController
const SECRET_KEY = process.env.JWT_SECRET; 
const DATA_PATH = path.join(process.cwd(), 'users.json')

export const getUsers = async () => {
    try {
        const data = await fs.readFile(DATA_PATH, 'utf-8');
        return JSON.parse(data);
    } catch { return []; }
};

export const createUser = async (username, password) => {
    const users = await getUsers();
    const hashedPassword = await bcrypt.hash(password, 10)
    const newUser = {
        username,
        password: hashedPassword,
        role: 'user',
        createdAt: new Date()
    }
    users.push(newUser)
    await fs.writeFile(DATA_PATH, JSON.stringify(users, null, 2))
}

export const verifyToken = (req, res, next) => {
    const token = req.cookies?.token;

    if (!token) {
        return res.status(401).json({ message: "กรุณาเข้าสู่ระบบ" });
    }
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        console.log(req.user)
        next();
    } catch (err) {
        return res.status(403).json({ message: "Token ไม่ถูกต้องหรือหมดอายุ" });
    }
};


