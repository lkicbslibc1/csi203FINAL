import express from 'express'
import cors from 'cors'
import authorization from './src/router/authorizationRouter.js'
import { verifyToken } from './src/controller/authorizationController.js'
import cookieParser from 'cookie-parser'
import path from 'path'
import { Server } from "socket.io";
import http from "http";
import jwt from 'jsonwebtoken';
import 'dotenv/config';
import os from 'os';
import mysql from 'mysql2';

// 1. เปลี่ยนมาใช้ createPool เพื่อความเสถียร (ป้องกันสายหลุด)
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '', 
    database: 'sniffer_db',
    timezone: 'Z',
    waitForConnections: true,
    connectionLimit: 10,     // เปิดท่อทิ้งไว้สูงสุด 10 ท่อ
    queueLimit: 0,           // ไม่จำกัดคิวการรอ
    enableKeepAlive: true,   // ส่งสัญญาณ Check-in กับ Database ตลอดเวลา
    keepAliveInitialDelay: 10000
});

// 2. ตรวจสอบการเชื่อมต่อ (Pool จะเริ่มทำงานเมื่อมีการเรียกใช้ครั้งแรก)
db.getConnection((err, connection) => {
    if (err) {
        console.error('❌ ต่อ MySQL ไม่ได้! เช็คดูว่ารัน MySQL หรือยัง (docker-compose up -d):', err.message);
    } else {
        console.log('✅ MySQL Connected via Pool! ท่อพร้อมใช้งานยาวๆ!');
        connection.release(); // คืนท่อเข้า Pool เพื่อให้คนอื่นใช้ต่อ
    }
});

// 3. แถม: ดักจับ Error เผื่อเคสฉุกเฉิน
db.on('error', (err) => {
    console.error('⚠️ DB Pool Error:', err.message);
    if (err.code === 'PROTOCOL_CONNECTION_LOST') {
        console.log('🔄 กำลังพยายามเชื่อมต่อใหม่...');
    }
});

const host = '0.0.0.0'
const port = 3000
const SECRET_KEY = process.env.JWT_SECRET;

const alertHistory = [];
const portScanTracker = new Map();   // srcIP -> { ports: Set, firstSeen: timestamp }
const bruteForceTracker = new Map(); // srcIP:dstPort -> { count, firstSeen }
const packetRateTracker = { count: 0, lastReset: Date.now() };

const ALERT_THRESHOLDS = {
    packetRatePerSec: 500,        // DoS threshold
    portScanCount: 15,            // unique ports in window = port scan
    portScanWindowMs: 5000,       // 5 second window
    bruteForceCount: 20,          // attempts in window
    bruteForceWindowMs: 10000,    // 10 second window
    certExpiryWarningDays: 30,
};

const INSECURE_PORTS = {
    21: { name: 'FTP', severity: 'HIGH' },
    23: { name: 'Telnet', severity: 'CRITICAL' },
    80: { name: 'HTTP', severity: 'MEDIUM' },
    8080: { name: 'HTTP', severity: 'MEDIUM' },
};

function createAlert(type, severity, message, details = {}) {
    const alert = {
        id: Date.now() + Math.random().toString(36).slice(2),
        type,
        severity,
        message,
        details,
        timestamp: new Date().toISOString(),
        _time: new Date().toLocaleTimeString(),
    };
    alertHistory.unshift(alert);
    if (alertHistory.length > 200) alertHistory.pop();
    io.emit('new_alert', alert);
    console.log(`เจอ [${severity}] ${type}: ${message}`);
    return alert;
}
const alertCooldowns = new Map();
function canAlert(key, cooldownMs = 10000) {
    const last = alertCooldowns.get(key);
    if (last && Date.now() - last < cooldownMs) return false;
    alertCooldowns.set(key, Date.now());
    return true;
}

function analyzePacketForAlerts(pkt) {
    pkt.alerts = []; // Attach alerts array to the packet
    const src = pkt.src;
    const dst = pkt.dst;
    const port = parseInt(pkt.port);
    const proto = pkt.protocol || '';

    if (INSECURE_PORTS[port]) {
        const { name, severity } = INSECURE_PORTS[port];
        pkt.alerts.push({ type: 'INSECURE_PROTOCOL', severity });
        const key = `insecure-${name}-${src}`;
        if (canAlert(key, 30000)) {
            createAlert('INSECURE_PROTOCOL', severity,
                `${name} traffic detected (unencrypted)`,
                { src, dst, port, protocol: name }
            );
        }
    }

    // Weak TLS Version
    const tlsVer = pkt.tls_version || '';
    if (tlsVer === 'SSL 3.0' || tlsVer === 'TLS 1.0' || tlsVer === 'TLS 1.1') {
        const severity = tlsVer === 'SSL 3.0' ? 'CRITICAL' : 'HIGH';
        pkt.alerts.push({ type: 'WEAK_TLS', severity });
        const key = `weaktls-${tlsVer}-${src}`;
        if (canAlert(key, 60000)) {
            createAlert('WEAK_TLS', severity,
                `Deprecated ${tlsVer} detected — vulnerable to known attacks`,
                { src, dst, tls_version: tlsVer }
            );
        }
    }

    if (pkt.cert_not_after && pkt.cert_not_after !== 'N/A') {
        try {
            const expiry = new Date(pkt.cert_not_after);
            const daysLeft = Math.floor((expiry - Date.now()) / 86400000);
            if (daysLeft >= 0 && daysLeft <= ALERT_THRESHOLDS.certExpiryWarningDays) {
                const key = `certexpiry-${pkt.cert_subject || dst}`;
                const severity = daysLeft <= 7 ? 'CRITICAL' : daysLeft <= 14 ? 'HIGH' : 'MEDIUM';
                pkt.alerts.push({ type: 'CERT_EXPIRY', severity });
                if (canAlert(key, 3600000)) {  // 1 hour cooldown
                    createAlert('CERT_EXPIRY', severity,
                        `Certificate expiring in ${daysLeft} day(s)`,
                        { src, dst, cert_subject: pkt.cert_subject, cert_not_after: pkt.cert_not_after, days_left: daysLeft }
                    );
                }
            }
        } catch (e) { }
    }
//ไอพีเดียวสุ่มมาหลายพอร์ตไหม
    if (port && src) {
        const now = Date.now();
        if (!portScanTracker.has(src)) {
            portScanTracker.set(src, { ports: new Set(), firstSeen: now });
        }
        const tracker = portScanTracker.get(src);
        if (now - tracker.firstSeen > ALERT_THRESHOLDS.portScanWindowMs) {
            tracker.ports = new Set();
            tracker.firstSeen = now;
        }
        tracker.ports.add(port);
        if (tracker.ports.size >= ALERT_THRESHOLDS.portScanCount) {
            pkt.alerts.push({ type: 'PORT_SCAN', severity: 'HIGH' });
            const key = `portscan-${src}`;
            if (canAlert(key, 30000)) {
                createAlert('PORT_SCAN', 'HIGH',
                    `Port scan detected from ${src} (${tracker.ports.size} ports in ${ALERT_THRESHOLDS.portScanWindowMs / 1000}s)`,
                    { src, ports_scanned: tracker.ports.size, sample_ports: [...tracker.ports].slice(0, 10) }
                );
            }
            // Reset after alert
            tracker.ports = new Set();
            tracker.firstSeen = now;
        }
    }

    // Brute Force Detection (SSH port 22, RDP port 3389)
    if ((port === 22 || port === 3389) && src) {
        const key = `${src}:${port}`;
        const now = Date.now();
        if (!bruteForceTracker.has(key)) {
            bruteForceTracker.set(key, { count: 0, firstSeen: now });
        }
        const bf = bruteForceTracker.get(key);
        if (now - bf.firstSeen > ALERT_THRESHOLDS.bruteForceWindowMs) {
            bf.count = 0;
            bf.firstSeen = now;
        }
        bf.count++;
        if (bf.count >= ALERT_THRESHOLDS.bruteForceCount) {
            pkt.alerts.push({ type: 'BRUTE_FORCE', severity: 'CRITICAL' });
            const alertKey = `bruteforce-${key}`;
            if (canAlert(alertKey, 60000)) {
                const service = port === 22 ? 'SSH' : 'RDP';
                createAlert('BRUTE_FORCE', 'CRITICAL',
                    `Brute force attempt on ${service} from ${src} (${bf.count} attempts in ${ALERT_THRESHOLDS.bruteForceWindowMs / 1000}s)`,
                    { src, dst, port, service, attempt_count: bf.count }
                );
            }
            bf.count = 0;
            bf.firstSeen = now;
        }
    }

    // 6. DoS / High Packet Rate (tracked per second in interval below)
    packetRateTracker.count++;
}

// DoS detection: check packet rate every second
setInterval(() => {
    const now = Date.now();
    const elapsed = (now - packetRateTracker.lastReset) / 1000;
    const rate = Math.floor(packetRateTracker.count / elapsed);
    if (rate >= ALERT_THRESHOLDS.packetRatePerSec) {
        if (canAlert('dos-rate', 15000)) {
            createAlert('DOS_ATTEMPT', 'CRITICAL',
                `High packet rate detected: ${rate} packets/sec (threshold: ${ALERT_THRESHOLDS.packetRatePerSec})`,
                { packets_per_sec: rate, threshold: ALERT_THRESHOLDS.packetRatePerSec }
            );
        }
    }
    packetRateTracker.count = 0;
    packetRateTracker.lastReset = now;
}, 1000);

// Cleanup old trackers every minute
setInterval(() => {
    const now = Date.now();
    for (const [ip, t] of portScanTracker) {
        if (now - t.firstSeen > 60000) portScanTracker.delete(ip);
    }
    for (const [key, t] of bruteForceTracker) {
        if (now - t.firstSeen > 60000) bruteForceTracker.delete(key);
    }
}, 60000);


const app = express()
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

app.use(express.json())
app.use(cookieParser());
app.use(express.static('.'));
app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        callback(null, true); 
    },
    credentials: true
}));

// --- Online Users Tracking ---
const onlineUsers = new Map(); // socketId -> { username, role, connectedAt }

function broadcastOnlineUsers() {
    const users = Array.from(onlineUsers.values());
    io.emit('online_users', users);
}

// --- Socket.io Logic ---
io.on('connection', (socket) => {
    console.log('👤 มีผู้ใช้งานเชื่อมต่อ:', socket.id);

    // รับ user identity จาก client
    socket.on('identify', (data) => {
        if (data && data.username) {
            let clientIp = socket.handshake.address;
            if (clientIp.startsWith('::ffff:')) {
                clientIp = clientIp.substring(7);
            }
            onlineUsers.set(socket.id, {
                users_id: data.users_id,
                username: data.username,
                role: data.role || 'user',
                connectedAt: new Date().toISOString(),
                socketId: socket.id,
                ip: clientIp
            });
            // console.log(`✅ User identified: ${data.users_id} ${data.username} (${data.role}) from IP: ${clientIp}`);
            broadcastOnlineUsers();
        }
    });

    socket.on('disconnect', () => {
        const user = onlineUsers.get(socket.id);
        if (user) {
            console.log(`👋 User disconnected: ${user.username}`);
            onlineUsers.delete(socket.id);
            broadcastOnlineUsers();
        }
    });

    // รับคำขอ online users
    socket.on('request_online_users', () => {
        broadcastOnlineUsers();
    });

    // รับคำขอรายชื่อจากหน้าเว็บ แล้วถาม Python
    socket.on('request_interfaces', () => {
        console.log('หน้าเว็บขอรายชื่อ... ');
        io.emit('request_interfaces');
    });

    // รับรายชื่อจาก Python แล้วส่งให้หน้าเว็บ
    socket.on('available_interfaces', (interfaces) => {
        console.log('ได้รับรายชื่อจาก Python แล้วส่งต่อให้ Web');
        io.emit('available_interfaces', interfaces);
    });

    // ส่งคำสั่ง Start/Stop
    socket.on('control_sniffer', (data) => {
        const user = onlineUsers.get(socket.id); //ไปเอาidของuser ถ่า้ใช้ip มันบัคได้เวลาเปิดหลายแท้บ
        if (user && data.action === 'start') {
            let who = '';
            if (user.role === 'admin') {
                who = ''; // Admin sniffs everything
            } else {
                who = `host ${user.ip}`;
            }
            data.filter = who;
        }
        console.log(data)
        console.log('คำสั่ง:', data.action, 'บน:', data.iface, 'Filter:', data.filter || 'None');
        io.emit('control_sniffer', data);
    });

    // ส่งข้อมูลแพ็กเก็ต
    socket.on('new_packet', (pkt) => {
        let mappedUser = null;
        let mappedUserId = null;

        // ลองหาว่า packet นี้ตรงกับ IP ของ user คนไหนที่ออนไลน์อยู่
        for (const user of onlineUsers.values()) {
            const UserIp = user.ip.replace('::ffff:', '');
            if (pkt.src === UserIp || pkt.dst === UserIp) {
                mappedUser = user.username;
                mappedUserId = user.users_id;
                break;
            }
        }
        
        pkt._user = mappedUser;
        pkt.users_id = mappedUserId;
        
        if (mappedUser === 'network') {
                    return;
                }
        analyzePacketForAlerts(pkt);
        const sql = `INSERT INTO packets (protocol, src, dst, port, size, encryption, cipher, cert, tls_version, handshake_type, payload, users_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
        const safePort = (pkt.port === '-' || isNaN(pkt.port)) ? 0 : pkt.port;

        const values = [
            
            pkt.protocol, pkt.src, pkt.dst, safePort, pkt.size,
            pkt.encryption, pkt.cipher, pkt.cert, pkt.tls_version,
            pkt.handshake_type, pkt.payload, pkt.users_id
        ];
        db.query(sql, values, (err, result) => {
            if (err) console.error("❌Insert ไม่เข้า:", err);
        });

        io.emit('update_dashboard', pkt);
    });



    socket.on('network_stats', (stats) => {
        io.emit('network_stats', stats);
    });
});

// --- Routes ---
app.get('/', (req, res) => res.sendFile(path.resolve('login.html')));
app.get('/admin', verifyToken, (req, res) => res.sendFile(path.resolve('admin.html')));
app.use('/auth', authorization);
app.get('/alerts', (req, res) => res.json(alertHistory));
app.put('/alerts/thresholds', (req, res) => {
    const { packetRatePerSec, portScanCount, bruteForceCount, certExpiryWarningDays } = req.body;
    if (packetRatePerSec) 
        {
            ALERT_THRESHOLDS.packetRatePerSec = packetRatePerSec;
        }
    if (portScanCount) 
        {
            ALERT_THRESHOLDS.portScanCount = portScanCount;
        }
    if (bruteForceCount) 
        {
            ALERT_THRESHOLDS.bruteForceCount = bruteForceCount;
        }
    if (certExpiryWarningDays) 
        {
            ALERT_THRESHOLDS.certExpiryWarningDays = certExpiryWarningDays;
        }
    res.json({ success: true, thresholds: ALERT_THRESHOLDS });
});

// ดึงประวัติการใช้งาน ของแอดมิน (ดึงข้อมูลทั้งหมดของทุกคน)
app.get('/api/history', verifyToken, (req, res) => {
    if (req.user.role === 'admin') {
        const sql = `
            SELECT packets.*, users.username 
            FROM packets 
            LEFT JOIN users ON packets.users_id = users.users_id 
            ORDER BY packets.id DESC
        `;
        db.query(sql, (err, results) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(results);
        });
    } else {
        const loggedInUser = req.user.users_id;
        console.log(loggedInUser)
        const sql = `
            SELECT packets.*, users.username 
            FROM packets 
            LEFT JOIN users ON packets.users_id = users.users_id 
            WHERE packets.users_id = ? 
            ORDER BY packets.id DESC 
            LIMIT 500
        `;
        db.query(sql, [loggedInUser], (err, results) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(results);
        });
    }
});
app.get('/api/packets/count', (req, res) => {
    db.query('SELECT COUNT(*) as total FROM packets', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ total: results[0].total });
    });
});
app.delete('/api/packets/me', verifyToken, (req, res) => {
    const loggedInUser = req.user.users_id;

    const sql = 'DELETE FROM packets WHERE users_id = ?';

    db.query(sql, [loggedInUser], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, deletedCount: result.affectedRows });
    });
});
app.delete('/api/packets/all', verifyToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'คุณไม่ใช่แอดมิน!' });
    }

    db.query('DELETE FROM packets', (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, message: 'ล้างข้อมูลเรียบร้อย!' });
    });
});
server.listen(port, host, () => {
    console.log(`🚀 Server running on http://${host}:${port}`);
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

import { fileURLToPath } from 'url';
import crypto from 'crypto';

// 1. จัดการเรื่อง Path สำหรับ ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// 2. Middleware
app.use(express.json()); // ใช้แทน bodyParser.json() ได้เลย
app.use(express.static(path.join(__dirname)));

// 3. ค่าคงที่ (เช็คให้ดี: AES-256 กุญแจต้องมี 32 bytes)
const IV_STRING = "ABCDEF0123456789"; // 16 characters

/**
 * ฟังก์ชันถอดรหัส (Reusable)
 */
function decryptData(encryptedData) {
    // แปลง Key และ IV ให้เป็น Buffer ตามที่ Node Crypto ต้องการ
    const ENCRYPTION_SECRET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
    const key = Buffer.from(ENCRYPTION_SECRET, 'utf8');
    const iv = Buffer.from(IV_STRING, 'utf8');

    // สร้าง Decipher โดยระบุ Algorithm, Key และ IV
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

    // ถอดรหัสจาก base64 เป็น utf8
    let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

// 4. Routes
app.post('/decrypt', (req, res) => {
    try {
        const encryptedData = req.body.data;

        if (!encryptedData) {
            return res.status(400).json({ error: 'ส่งข้อมูล (data) มาด้วยมึง' });
        }

        console.log('--- New Request ---');
        console.log('Encrypted data (Base64):', encryptedData);

        const decryptedText = decryptData(encryptedData);

        console.log('Decrypted result:', decryptedText);

        res.json({
            success: true,
            decryptedText: decryptedText
        });

    } catch (error) {
        console.error('Decryption failed:', error.message);

        // ถ้า Key หรือ IV ผิด หรือ Data ไม่ใช่ Base64 มันจะวิ่งมาที่นี่
        res.status(500).json({
            success: false,
            error: 'การถอดรหัสผิดพลาด: ' + error.message
        });
    }
});