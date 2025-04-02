const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = 3000;

// Настройка middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

// Настройка сессий
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: false, // В production должно быть true для HTTPS
        maxAge: 24 * 60 * 60 * 1000 // 24 часа
    }
}));

// Хранение пользователей (в реальном приложении используйте БД)
const users = [];

// Хранение кэша
const cache = {
    data: null,
    timestamp: null
};

// Middleware для проверки аутентификации
function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Не авторизован' });
    }
    next();
}

// Роуты
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Проверка на существующего пользователя
        if (users.some(u => u.username === username)) {
            return res.status(400).json({ error: 'Пользователь уже существует' });
        }
        
        // Хэширование пароля
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Сохранение пользователя
        users.push({ username, password: hashedPassword });
        
        res.status(201).json({ message: 'Пользователь зарегистрирован' });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = users.find(u => u.username === username);
        
        if (!user) {
            return res.status(401).json({ error: 'Неверные учетные данные' });
        }
        
        // Проверка пароля
        const match = await bcrypt.compare(password, user.password);
        
        if (!match) {
            return res.status(401).json({ error: 'Неверные учетные данные' });
        }
        
        // Создание сессии
        req.session.user = { username };
        
        res.json({ message: 'Вход выполнен успешно' });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка выхода' });
        }
        res.clearCookie('connect.sid');
        res.json({ message: 'Выход выполнен успешно' });
    });
});

app.get('/profile', requireAuth, (req, res) => {
    res.json({ username: req.session.user.username });
});

app.get('/data', (req, res) => {
    const now = Date.now();
    const cacheFile = path.join(__dirname, 'cache.json');
    
    // Проверка кэша в памяти
    if (cache.data && cache.timestamp && (now - cache.timestamp < 60000)) {
        return res.json({ data: cache.data, source: 'memory cache' });
    }
    
    // Проверка файлового кэша
    try {
        if (fs.existsSync(cacheFile)) {
            const stats = fs.statSync(cacheFile);
            if (now - stats.mtimeMs < 60000) {
                const fileData = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
                // Обновляем кэш в памяти
                cache.data = fileData.data;
                cache.timestamp = stats.mtimeMs;
                return res.json({ data: fileData.data, source: 'file cache' });
            }
        }
    } catch (err) {
        console.error('Ошибка чтения кэша:', err);
    }
    
    // Генерация новых данных
    const newData = {
        timestamp: now,
        value: `Случайные данные: ${Math.random().toString(36).substring(2, 15)}`
    };
    
    // Сохранение в кэш памяти
    cache.data = newData;
    cache.timestamp = now;
    
    // Сохранение в файловый кэш
    fs.writeFile(cacheFile, JSON.stringify({ data: newData }), err => {
        if (err) console.error('Ошибка записи кэша:', err);
    });
    
    res.json({ data: newData, source: 'new data' });
});

// Запуск сервера
app.listen(PORT, () => {
    console.log(`Сервер запущен на http://localhost:${PORT}`);
});