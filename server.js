const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Подключение к MongoDB
mongoose.connect('mongodb://localhost:27017/political_monitoring', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => console.log('Подключено к MongoDB'))
    .catch((err) => console.error('Ошибка подключения к MongoDB:', err));

// Модель пользователя
const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// Модель для результатов опроса
const pollSchema = new mongoose.Schema({
    party: { type: String, required: true }, // Название партии
    votes: { type: Number, default: 0 },    // Количество голосов
});

const Poll = mongoose.model('Poll', pollSchema);

// Модель для отслеживания голосов пользователя
const userVoteSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    lastVoteDate: { type: Date, default: null }, // Дата последнего голосования
});

const UserVote = mongoose.model('UserVote', userVoteSchema);

// Middleware для проверки токена
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1]; // Получаем токен из заголовка Authorization

    if (!token) {
        return res.status(401).json({ message: 'Доступ запрещен. Отсутствует токен.' });
    }

    jwt.verify(token, 'your_secret_key', (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Недействительный токен.' });
        }

        req.user = user; // Добавляем пользователя в запрос
        next(); // Переходим к следующему middleware
    });
}

// Роут для регистрации
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Проверяем, существует ли пользователь с таким email
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ message: 'Пользователь с таким email уже существует.' });
        }

        // Хешируем пароль
        const hashedPassword = await bcrypt.hash(password, 10);

        // Создаем нового пользователя
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'Регистрация успешна!' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Ошибка сервера.' });
    }
});

// Роут для входа
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Находим пользователя по email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Неверный email или пароль.' });
        }

        // Сверяем пароль
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Неверный email или пароль.' });
        }

        // Генерируем JWT-токен
        const token = jwt.sign({ userId: user._id }, 'your_secret_key', { expiresIn: '1h' });

        res.json({ message: 'Вход выполнен успешно!', token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Ошибка сервера.' });
    }
});

// Роут для голосования
app.post('/api/poll/vote', authenticateToken, async (req, res) => {
    try {
        const { party } = req.body;
        const userId = req.user.userId;

        // Проверяем, голосовал ли пользователь в этом месяце
        const userVote = await UserVote.findOne({ userId });
        if (userVote && userVote.lastVoteDate) {
            const lastVoteMonth = userVote.lastVoteDate.getMonth();
            const currentMonth = new Date().getMonth();

            if (lastVoteMonth === currentMonth) {
                return res.status(403).json({ message: 'Вы уже проголосовали в этом месяце.' });
            }
        }

        // Обновляем или создаем запись о голосовании пользователя
        if (!userVote) {
            await new UserVote({ userId, lastVoteDate: new Date() }).save();
        } else {
            userVote.lastVoteDate = new Date();
            await userVote.save();
        }

        // Обновляем количество голосов для выбранной партии
        const poll = await Poll.findOne({ party });
        if (poll) {
            poll.votes += 1;
            await poll.save();
        } else {
            await new Poll({ party, votes: 1 }).save();
        }

        res.json({ message: 'Голос успешно учтен!' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Ошибка сервера.' });
    }
});

// Получение результатов опроса
app.get('/api/poll/results', async (req, res) => {
    try {
        const results = await Poll.find();
        res.json(results);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Ошибка сервера.' });
    }
});

// Пример защищенного маршрута
app.get('/api/profile', authenticateToken, (req, res) => {
    res.json({ message: 'Это ваш профиль!', user: req.user });
});

// Инициализация данных опроса при старте сервера
app.listen(process.env.PORT || 3000, async () => {
    console.log(`Сервер запущен на порту ${process.env.PORT || 3000}`);

    // Создаем записи для всех партий, если их нет
    const parties = ['edinaya-rossiya', 'kprf', 'ldpr', 'sprr', 'novye-lyudi'];
    for (const party of parties) {
        const existingPoll = await Poll.findOne({ party });
        if (!existingPoll) {
            await new Poll({ party, votes: 0 }).save();
        }
    }
});