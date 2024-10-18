const express = require('express');
const pool = require("./database");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const port = 4000;

const asyncHandler = fn => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

app.get('/', (req, res) => res.send('Hello World!'));

app.post('/register', asyncHandler(async (req, res) => {
    const { email, password, name } = req.body;

    const [existingUser] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUser.length > 0) {
        return res.status(400).json({ message: 'Email นี้ถูกลงทะเบียนแล้ว' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query('INSERT INTO users (email, password, name) VALUES (?, ?, ?)', [email, hashedPassword, name]);

    res.status(201).json({ message: 'ลงทะเบียนผู้ใช้สำเร็จ', userId: result.insertId });
}));

app.post('/login', asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'กรุณากรอกอีเมลและรหัสผ่าน' });
    }

    const [results] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    const user = results[0];

    if (!user) {
        return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
    }

    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
        return res.status(401).json({ message: 'รหัสผ่านไม่ถูกต้อง' });
    }

    const accessToken = jwt.sign(
        { id: user.id, email: user.email },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '20h' }
    );

    return res.json({ token: accessToken, isAdmin: user.role === 'admin' });
}));

app.post('/addnew', asyncHandler(async (req, res) => {
    const { email, fname, lname, password, name, role } = req.body;

    if (!email || !fname || !lname || !password) {
        return res.status(400).json({ message: 'กรุณาส่งข้อมูลให้ครบ (email, fname, lname, password)' });
    }

    try {
        await pool.query('START TRANSACTION');

        const [existingUserInUsers] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        const [existingUserInEmployees] = await pool.query('SELECT * FROM employees WHERE email = ?', [email]);

        if (existingUserInUsers.length > 0 || existingUserInEmployees.length > 0) {
            return res.status(400).json({ message: 'Email นี้ถูกลงทะเบียนแล้ว' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const [userResult] = await pool.query(
            'INSERT INTO users (email, password, name, role) VALUES (?, ?, ?, ?)',
            [email, hashedPassword, name || null, role || 'user']
        );

        await pool.query(
            'INSERT INTO employees (email, fname, lname) VALUES (?, ?, ?)',
            [email, fname, lname]
        );

        await pool.query('COMMIT');

        res.status(201).json({ message: 'เพิ่มผู้ใช้สำเร็จ', userId: userResult.insertId });
    } catch (error) {
        await pool.query('ROLLBACK');
        console.error('Error adding new user:', error);
        res.status(500).json({ message: 'เกิดข้อผิดพลาดในการเพิ่มผู้ใช้' });
    }
}));


app.get('/users/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;

    // ดึงข้อมูลจาก users และ employees โดยใช้ email เป็นตัวเชื่อม
    const [user] = await pool.query(`
        SELECT u.id, u.email, u.name, u.role, u.created_at, 
               e.fname, e.lname
        FROM users u
        LEFT JOIN employees e ON u.email = e.email
        WHERE u.id = ?
    `, [id]);

    if (user.length === 0) {
        return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
    }

    // ส่งข้อมูลผู้ใช้กลับไป
    res.json(user[0]);
}));

app.get('/users', asyncHandler(async (req, res) => {
    const [users] = await pool.query(`
        SELECT u.id, u.email, u.name, u.role,
               COALESCE(e.fname, 'N/A') AS fname, 
               COALESCE(e.lname, 'N/A') AS lname
        FROM users u
        LEFT JOIN employees e ON u.email = e.email
        GROUP BY u.id, u.email
    `);

    if (users.length === 0) {
        return res.status(404).json({ message: 'ไม่พบข้อมูลผู้ใช้' });
    }

    res.json(users);
}));

app.put('/users/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { name, email, fname, lname } = req.body;

    // ตรวจสอบผู้ใช้ในตาราง users
    const [user] = await pool.query('SELECT * FROM users WHERE id = ?', [id]);
    if (user.length === 0) {
        return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
    }

    // อัปเดตข้อมูลในตาราง users
    try {
        await pool.query('UPDATE users SET name = ?, email = ? WHERE id = ?', [name, email, id]);
    } catch (error) {
        return res.status(500).json({ message: 'เกิดข้อผิดพลาดในการอัปเดตข้อมูลผู้ใช้', error: error.message });
    }

    // ตรวจสอบว่ามีอีเมลนี้ในตาราง employees หรือไม่
    const [employee] = await pool.query('SELECT * FROM employees WHERE email = ?', [email]);

    try {
        if (employee.length === 0) {
            // หากไม่มี ให้เพิ่มข้อมูลใหม่
            await pool.query('INSERT INTO employees (email, fname, lname) VALUES (?, ?, ?)', [email, fname, lname]);
        } else {
            // หากมีอีเมลอยู่แล้ว ให้ทำการอัปเดตข้อมูล fname และ lname
            await pool.query('UPDATE employees SET fname = ?, lname = ? WHERE email = ?', [fname, lname, email]);
        }
    } catch (error) {
        return res.status(500).json({ message: 'เกิดข้อผิดพลาดในการอัปเดตข้อมูลพนักงาน', error: error.message });
    }

    // ดึงข้อมูลผู้ใช้ที่อัปเดตกลับมาแสดง
    const [updatedUser] = await pool.query(`
        SELECT u.id, u.email, u.name, 
               COALESCE(e.fname, 'N/A') AS fname, 
               COALESCE(e.lname, 'N/A') AS lname
        FROM users u
        LEFT JOIN employees e ON u.email = e.email
        WHERE u.id = ?
    `, [id]);

    res.json(updatedUser[0]);
}));

app.delete('/users/:id', asyncHandler(async (req, res) => {
    const { id } = req.params;
    const [user] = await pool.query('SELECT * FROM users WHERE id = ?', [id]);

    if (user.length === 0) {
        return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
    }

    await pool.query('DELETE FROM users WHERE id = ?', [id]);
    await pool.query('DELETE FROM employees WHERE email = ?', [user[0].email]);

    res.json({ message: 'ลบผู้ใช้สำเร็จ' });
}));

// ตรวจสอบและสร้างโฟลเดอร์ 'uploads' หากไม่มีอยู่
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// กำหนดโฟลเดอร์สำหรับเก็บรูป
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

app.use('/uploads', express.static('uploads'));

// ตรวจสอบ user token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// ดึงข้อมูลบัญชีผู้ใช้
app.get('/account', authenticateToken, async (req, res) => {
    try {
        const userid = req.user.id;
        const [results] = await pool.query("SELECT email, name, picture FROM users WHERE id =?", [userid])
        if (results.length === 0) {
            return res.status(404).json({ error: "ไม่พบผู้ใช้" })
        }
        res.json(results);
    } catch (err) {
        console.log(err);
        res.status(500).json({ error: "ผิดพลาด" });
    }
});

// อัปเดตข้อมูลบัญชีผู้ใช้
app.post('/account/update', authenticateToken, upload.single('picture'), async (req, res) => {
    try {
        const userid = req.user.id;
        const { name, email } = req.body;
        let picture = req.file ? `/uploads/${req.file.filename}` : null;

        // ดึงข้อมูลผู้ใช้ปัจจุบัน
        const [user] = await pool.query("SELECT * FROM users WHERE id = ?", [userid]);
        if (user.length === 0) {
            return res.status(404).json({ message: "ไม่พบผู้ใช้" });
        }

        // อัปเดตข้อมูลในฐานข้อมูล
        await pool.query(
            "UPDATE users SET name = ?, email = ?, picture = COALESCE(?, picture) WHERE id = ?",
            [name, email, picture, userid]
        );

        res.status(200).json({ message: "อัปเดตข้อมูลสำเร็จ" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "ผิดพลาดในการอัปเดตข้อมูลผู้ใช้" });
    }
});


// ############# เพิ่มใน server.js ##############

// โพสบล็อกใหม่่
app.post('/create-post', authenticateToken, async (req, res) => {
    const { title, detail, category } = req.body;
    try {
        const userid = req.user.id; // ใช้ user id จาก JWT
        const [result] = await pool.query(
            'INSERT INTO blog (userid, title, detail, category) VALUES (?, ?, ?, ?)',
            [userid, title, detail, category]
        );
        res.status(201).json({ message: "โพสต์ถูกสร้างเรียบร้อย", postId: result.insertId });
    } catch (err) {
        res.status(500).json({ error: "ไม่สามารถสร้างโพสต์ได้" });
    }
});


// แสดงโพสทั้งหมดตาม user
app.get('/read-post/', authenticateToken, async (req, res) => {
    try {
        const userid = req.user.id;
        const [results] = await pool.query('SELECT * FROM blog WHERE userid = ?', [userid])
        if (results.length === 0) {
            return res.status(404).json({ error: "ไม่พบบทความ" })
        }
        res.json(results)
    } catch (err) {
        console.log(err)
        res.status(500).json({ error: "ไม่สามารถดึงข้อมูลได้" })
    }
});

// ดึงข้อมูล blog ตาม id
app.get('/post/:blogid', async (req, res) => {
    const { blogid } = req.params; // ดึงค่า blogid จาก URL Parameters
    try {
        // คำสั่ง SQL สำหรับดึงข้อมูลบล็อกจากฐานข้อมูล
        const [result] = await pool.query('SELECT * FROM blog WHERE blogid = ?', [blogid]);
        // ตรวจสอบว่าพบบล็อกหรือไม่
        if (result.length === 0) {
            return res.status(404).json({ message: 'Blog not found' });
        }
        // ส่งข้อมูลบล็อกที่พบกลับไปยัง client
        return res.json(result[0]);
    } catch (err) {
        console.error("Error fetching blog data: ", err); // แสดงข้อผิดพลาดใน console
        return res.status(500).json({ message: 'Error fetching blog data', error: err });
    }
});

// ลบข้อมูล blog
app.delete('/post/:blogid', async (req, res) => {
    const { blogid } = req.params;
    try {
        const [result] = await pool.query('DELETE FROM blog WHERE blogid = ?', [blogid]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Blog not found' });
        }
        return res.json({ message: 'Blog deleted successfully' });
    } catch (err) {
        console.error("Error executing SQL: ", err); // ตรวจสอบข้อผิดพลาด SQL
        return res.status(500).json({ message: 'Error deleting the blog', error: err });
    }
});

// แก้ไขข้อมูล blog
app.put('/post/:blogid', async (req, res) => {
    const { blogid } = req.params;
    const { title, detail, category } = req.body;
    try {
        const [result] = await pool.query(
            'UPDATE blog SET title = ?, detail = ?, category = ? WHERE blogid = ?',
            [title, detail, category, blogid]
        );
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Blog not found' });
        }
        return res.json({ message: 'Blog updated successfully' });
    } catch (err) {
        console.error("Error updating SQL: ", err); // ตรวจสอบข้อผิดพลาด SQL
        return res.status(500).json({ message: 'Error updating the blog', error: err });
    }
});

app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ message: 'เกิดข้อผิดพลาดในระบบ' });
});

app.listen(port, () => {
    console.log(`Server กำลังทำงานที่ port ${port}`);
});
