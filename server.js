const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const app = express();
app.use(bodyParser.json());
app.use(cors());

const PORT = process.env.PORT || 5001;
const JWT_SECRET = 'sGv9r1o2U4x5Z8t7w6v3r9b2Y6u5Q1p0';

const uri = "mongodb+srv://admin:admin@formularz.kwwftsk.mongodb.net/?appName=formularz";

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

client.connect()
  .then(() => {
    console.log("Successfully connected to MongoDB Atlas");

    const db = client.db('formularz');
    const usersCollection = db.collection('users');

    const cryptocurrencyValues = {
      'Dogecoin': 1.05,
      'Shiba Inu': 0.10,
      'Terra Classic': 0.50,
      'VeChain': 1.20,
      'Stellar': 0.25,
      'Tron': 0.30,
      'Dash': 200,
      'Zcash': 150,
      'Chainlink': 25,
      'Uniswap': 30,
      'Litecoin': 180,
      'Bitcoin Cash': 600,
      'Cardano': 3.50,
      'Polkadot': 25,
      'Solana': 45,
      'Avalanche': 40,
      'Ethereum': 3000,
      'Binance Coin': 500,
      'Bitcoin': 50000,
      'Tether': 1
    };

    const quests = [
      { level: 2, requirements: { 1: 10 } },
      { level: 3, requirements: { 1: 20, 2: 50 } },
      { level: 4, requirements: { 2: 100, 3: 200 } },
      { level: 5, requirements: { 3: 250, 4: 400 } }
    ];

    app.post('/register', async (req, res) => {
      const { username, password } = req.body;
      const hashedPassword = await bcrypt.hash(password, 10);
      try {
        const user = { username, password: hashedPassword, cryptocurrencies: [], creationDate: new Date(), level: 1 };
        await usersCollection.insertOne(user);
        res.status(201).send('User created');
      } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).send('Error registering user');
      }
    });

    app.post('/login', async (req, res) => {
      const { username, password } = req.body;
      const user = await usersCollection.findOne({ username });
      if (!user) {
        return res.status(401).send('Invalid credentials');
      }
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).send('Invalid credentials');
      }
      const token = jwt.sign({ id: user._id }, JWT_SECRET);
      res.json({ token });
    });

    const authMiddleware = (req, res, next) => {
      const token = req.headers['authorization'];
      if (!token) {
        return res.status(401).send('Access denied');
      }
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.id;
        next();
      } catch (error) {
        res.status(401).send('Invalid token');
      }
    };

    const calculateTotalValue = (cryptocurrencies) => {
      return cryptocurrencies.reduce((acc, crypto) => {
        return acc + (crypto.amount * cryptocurrencyValues[crypto.name]);
      }, 0);
    };

    const checkQuestCompletion = (user) => {
      const userLevel = user.level;
      const nextQuest = quests.find(q => q.level === userLevel + 1);
      if (!nextQuest) return false;

      for (const [level, value] of Object.entries(nextQuest.requirements)) {
        const userCrypto = user.cryptocurrencies.filter(c => c.level === parseInt(level));
        const totalValue = calculateTotalValue(userCrypto);
        if (totalValue < value) return false;
      }
      return true;
    };

    app.get('/profile', authMiddleware, async (req, res) => {
      const user = await usersCollection.findOne({ _id: new ObjectId(req.userId) });
      if (!user) {
        return res.status(404).send('User not found');
      }
      res.json({ username: user.username, cryptocurrencies: user.cryptocurrencies, creationDate: user.creationDate, level: user.level });
    });

    app.get('/quests', authMiddleware, async (req, res) => {
      const user = await usersCollection.findOne({ _id: new ObjectId(req.userId) });
      if (!user) {
        return res.status(404).send('User not found');
      }
      const userLevel = user.level;
      const nextQuest = quests.find(q => q.level === userLevel + 1);
      res.json(nextQuest || {});
    });

    const cryptocurrenciesByLevel = {
      1: ['Dogecoin', 'Shiba Inu', 'Terra Classic', 'VeChain'],
      2: ['Stellar', 'Tron', 'Dash', 'Zcash'],
      3: ['Chainlink', 'Uniswap', 'Litecoin', 'Bitcoin Cash'],
      4: ['Cardano', 'Polkadot', 'Solana', 'Avalanche'],
      5: ['Ethereum', 'Binance Coin', 'Bitcoin', 'Tether']
    };

    app.post('/mine', authMiddleware, async (req, res) => {
      const { level } = req.body; // Otrzymujemy poziom z żądania
      if (!cryptocurrenciesByLevel[level]) {
        return res.status(400).send('Invalid mining level');
      }

      try {
        const user = await usersCollection.findOne({ _id: new ObjectId(req.userId) });
        if (!user) {
          return res.status(404).send('User not found');
        }

        if (level > user.level) {
          return res.status(403).send('Level locked');
        }

        const cryptocurrencies = cryptocurrenciesByLevel[level];
        const minedCrypto = cryptocurrencies[Math.floor(Math.random() * cryptocurrencies.length)];
        const minedAmount = (Math.random() * 0.2).toFixed(6); // Losowa ilość od 0 do 0.2

        const existingCryptoIndex = user.cryptocurrencies.findIndex(c => c.name === minedCrypto && c.level === level);
        if (existingCryptoIndex > -1) {
          user.cryptocurrencies[existingCryptoIndex].amount += parseFloat(minedAmount);
        } else {
          user.cryptocurrencies.push({ name: minedCrypto, amount: parseFloat(minedAmount), level });
        }

        await usersCollection.updateOne(
          { _id: new ObjectId(req.userId) },
          { $set: { cryptocurrencies: user.cryptocurrencies } }
        );

        const updatedUser = await usersCollection.findOne({ _id: new ObjectId(req.userId) });
        const questCompleted = checkQuestCompletion(updatedUser);

        if (questCompleted) {
          await usersCollection.updateOne(
            { _id: new ObjectId(req.userId) },
            { $set: { level: user.level + 1 } }
          );
          res.status(200).send(`Mining successful: ${minedAmount} ${minedCrypto}. Awansowałeś! Gratulacje!`);
        } else {
          res.status(200).send(`Mining successful: ${minedAmount} ${minedCrypto}`);
        }
      } catch (error) {
        res.status(500).send('Mining failed');
      }
    });

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });

  })
  .catch(err => {
    console.error("Connection error", err);
  });
