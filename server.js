const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// Middleware
app.use(bodyParser.json());
app.use(cors());  // Это позволит вашему фронтенду обращаться к серверу с другого порта

// Подключение к MongoDB
mongoose.connect('mongodb://localhost:27017/political_monitoring', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => console.log('Подключено к MongoDB'))
    .catch((err) => console.error('Ошибка подключения к MongoDB:', err));

// Модели
const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

const pollSchema = new mongoose.Schema({
    party: { type: String, required: true }, // Сохраняем английские названия партий
    votes: { type: Number, default: 0 },
});

const Poll = mongoose.model('Poll', pollSchema);

const userVoteSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    lastVoteDate: { type: Date, default: null },
});

const UserVote = mongoose.model('UserVote', userVoteSchema);

// Middleware для проверки токена
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Доступ запрещен.' });

    jwt.verify(token, 'your_secret_key', (err, user) => {
        if (err) return res.status(403).json({ message: 'Недействительный токен.' });
        req.user = user;
        next();
    });
}

// Роуты
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(409).json({ message: 'Пользователь уже существует.' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ message: 'Регистрация успешна!' });
    } catch (error) {
        res.status(500).json({ message: 'Ошибка сервера.' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(401).json({ message: 'Неверный email или пароль.' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'Неверный email или пароль.' });

        const token = jwt.sign({ userId: user._id }, 'your_secret_key', { expiresIn: '1h' });
        res.json({ message: 'Вход выполнен успешно!', token });
    } catch (error) {
        res.status(500).json({ message: 'Ошибка сервера.' });
    }
});

app.post('/api/poll/vote', authenticateToken, async (req, res) => {
    try {
        const { party } = req.body;
        const userId = req.user.userId;

        // Проверяем, проголосовал ли пользователь в этом месяце
        const userVote = await UserVote.findOne({ userId });
        if (userVote && userVote.lastVoteDate.getMonth() === new Date().getMonth()) {
            return res.status(403).json({ message: 'Вы уже проголосовали в этом месяце.' });
        }

        // Обновляем или создаем запись о голосе пользователя
        if (!userVote) {
            await new UserVote({ userId, lastVoteDate: new Date() }).save();
        } else {
            userVote.lastVoteDate = new Date();
            await userVote.save();
        }

        // Обновляем количество голосов для партии
        const poll = await Poll.findOne({ party });
        if (poll) {
            poll.votes += 1;
            await poll.save();
        } else {
            await new Poll({ party, votes: 1 }).save();
        }

        res.json({ message: 'Голос успешно учтен!' });
    } catch (error) {
        res.status(500).json({ message: 'Ошибка сервера.' });
    }
});

app.get('/api/poll/results', async (req, res) => {
    try {
        const results = await Poll.find();
        res.json(results);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Ошибка сервера.' });
    }
});

// Запуск сервера
app.listen(process.env.PORT || 3000, async () => {
    console.log(`Сервер запущен на порту ${process.env.PORT || 3000}`);
    const parties = ['edinaya_rossiya', 'kprf', 'ldpr', 'sprr', 'novye_lyudi'];
    for (const party of parties) {
        const existingPoll = await Poll.findOne({ party });
        if (!existingPoll) await new Poll({ party, votes: 0 }).save();
    }
});