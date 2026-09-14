const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const pool = require('./db');

const app = express();
app.use(express.json());
app.use(cors());

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
    const [salt, key] = storedHash.split(':');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(key, 'hex'));
}

app.post('/api/register', async (req, res) => {
    const connection = await pool.getConnection();
    try {
        const { name, phone, password } = req.body;
        if (!name || !phone || !password) {
            connection.release();
            return res.status(400).json({ error: 'নাম, মোবাইল নম্বর ও পাসওয়ার্ড দিন!' });
        }
        await connection.beginTransaction();
        const hashedPassword = hashPassword(password);
        const [userRes] = await connection.query(
            'INSERT INTO users (name, phone, password) VALUES (?, ?, ?)',
            [name, phone, hashedPassword]
        );
        const userId = userRes.insertId;
        await connection.query(
            'INSERT INTO wallets (user_id, balance) VALUES (?, 0.00)',
            [userId]
        );
        await connection.commit();
        connection.release();
        res.status(201).json({ message: 'রেজিস্ট্রেশন সফল হয়েছে!', userId });
    } catch (error) {
        await connection.rollback();
        connection.release();
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'এই মোবাইল নম্বর দিয়ে আগেই অ্যাকাউন্ট খোলা হয়েছে!' });
        }
        console.error(error);
        res.status(500).json({ error: 'সার্ভারে সমস্যা হয়েছে!' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { phone, password } = req.body;
        if (!phone || !password) {
            return res.status(400).json({ error: 'মোবাইল নম্বর ও পাসওয়ার্ড দিন!' });
        }
        const [rows] = await pool.query('SELECT * FROM users WHERE phone = ?', [phone]);
        if (rows.length === 0) {
            return res.status(401).json({ error: 'ব্যবহারকারী পাওয়া যায়নি!' });
        }
        const user = rows[0];
        const isValid = verifyPassword(password, user.password);
        if (!isValid) {
            return res.status(401).json({ error: 'ভুল পাসওয়ার্ড!' });
        }
        res.json({
            message: 'লগইন সফল হয়েছে!',
            user: { id: user.id, name: user.name, phone: user.phone }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'সার্ভারে সমস্যা হয়েছে!' });
    }
});

app.post('/api/deposit', async (req, res) => {
    try {
        const { userId, gateway, amount, trxId } = req.body;
        if (!userId || !gateway || !amount || !trxId) {
            return res.status(400).json({ error: 'সব ফিল্ড পূরণ করুন!' });
        }
        const [result] = await pool.query(
            'INSERT INTO deposits (user_id, gateway, amount, trx_id, status) VALUES (?, ?, ?, ?, "pending")',
            [userId, gateway, amount, trxId]
        );
        res.status(201).json({ message: 'ডিপোজিট রিকোয়েস্ট সফল হয়েছে!', depositId: result.insertId });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'সার্ভারে সমস্যা হয়েছে!' });
    }
});

app.get('/api/balance/:userId', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT balance FROM wallets WHERE user_id = ?', [req.params.userId]);
        if (rows.length > 0) {
            res.json({ balance: rows[0].balance });
        } else {
            res.json({ balance: 0.00 });
        }
    } catch (error) {
        res.status(500).json({ error: 'ব্যালেন্স লোড করতে সমস্যা হয়েছে!' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
