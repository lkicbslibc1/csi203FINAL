import { Router } from 'express';
import { createUser, getUsers, verifyToken, pool } from '../controller/authorizationController.js';
import 'dotenv/config'; 
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const SECRET_KEY = process.env.JWT_SECRET; 
const authorization = Router();

authorization.post("/register", async (req, res) => {
    const { username, password } = req.body;
    try {
        const users = await getUsers();
        const userExists = users.find(u => u.username === username);
        if (userExists) {
            return res.status(400).json({ message: "ชื่อผู้ใช้งานนี้มีคนใช้แล้ว" });
        }
        await createUser(username, password);
        return res.status(200).json({ message: 'success' });
    } catch (error) {
        console.error("DATABASE ERROR:", error);
        return res.status(500).json({
            message: 'Internal Server Error',
            error: error.message
        });
    }
});

authorization.post("/login", async(req, res) => {
    const { username, password } = req.body;
    const users = await getUsers();
    const user = users.find(u => u.username === username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" });
    }

    const token = jwt.sign(
        { username: user.username, role: user.role },
        SECRET_KEY,
        { expiresIn: '1h' }
    );
    res.cookie('token', token, {
        httpOnly: true,  
        secure: false, 
        sameSite: 'lax', 
        maxAge: 3600000  
    });

    return res.status(200).json({ 
        message: 'Login success',
        role: user.role 
    });
});

authorization.get("/me", verifyToken, async(req,res)=>{
    if (!req.user) {
        return res.status(401).json({ message: "ไม่พบข้อมูลผู้ใช้" });
    }
    res.status(200).json({
        success: true,
        user: {
            username: req.user.username,
            role: req.user.role
        }
    });
});

authorization.post("/logout", async(req,res) => {
    res.clearCookie('token', {
        httpOnly: true,
        sameSite: 'lax',
        secure: false
    });
    return res.status(200).json({ message: "Logout successful" });
});

// === Admin APIs ===
const requireAdmin = (req, res, next) => {
    if (req.user?.role !== 'admin') return res.status(403).json({ message: 'Admin only' });
    next();
};

authorization.get("/users", verifyToken, requireAdmin, async (req, res) => {
    const users = await getUsers();
    const safe = users.map(u => ({ username: u.username, role: u.role, createdAt: u.createdAt }));
    res.json(safe);
});

authorization.put("/users/:username/role", verifyToken, requireAdmin, async (req, res) => {
    const { role } = req.body;
    if (!['admin','user'].includes(role)) return res.status(400).json({ message: 'Invalid role' });
    
    await pool.query('UPDATE users SET role = ? WHERE username = ?', [role, req.params.username]);
    res.json({ message: 'Role updated' });
});

authorization.delete("/users/:username", verifyToken, requireAdmin, async (req, res) => {
    if (req.params.username === req.user.username) return res.status(400).json({ message: 'Cannot delete yourself' });
    
    const [result] = await pool.query('DELETE FROM users WHERE username = ?', [req.params.username]);
    if (result.affectedRows === 0) return res.status(404).json({ message: 'User not found' });
    
    res.json({ message: 'User deleted' });
});

export default authorization;