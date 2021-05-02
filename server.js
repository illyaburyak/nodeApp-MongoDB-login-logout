const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const User = require('./model/user.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = 'ngioekrnagaojglwnfoveqrjgnaln';

mongoose.connect('mongodb://localhost:27017/login-app-db', {
  useNewUrlParser: true,
  useFindAndModify: true,
  useUnifiedTopology: true,
  useCreateIndex: true,
});

const app = express();

const port = 3000;
app.use('/', express.static(path.join(__dirname, 'static')));

app.use(express.json());

app.post('/api/change-password', async (req, res) => {
  const { token, newPassword } = req.body;
  try {
    const user = jwt.verify(token, JWT_SECRET);

    const _id = user.id;
    const hashedPassword = await bcrypt.hash(newPassword, 8);

    await User.updateOne(
      { _id },
      {
        $set: { password: hashedPassword },
      },
    );
    res.json({ status: 'ok' });
    console.log(user);
  } catch (e) {
    console.log(user);
    res.json({ status: 'error', error: 'wow' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username }).lean();

  if (!user) {
    return res.json({ status: 'error', error: 'Invalid username or password' });
  }
  if (await bcrypt.compare(password, user.password)) {
    // the username, password combination is successful
    const token = jwt.sign(
      {
        id: user._id,
        username: user.username,
      },
      JWT_SECRET,
    );

    return res.json({ status: 'ok', data: '' });
  }

  res.json({ status: 'error', error: 'Invalid username or password' });
});

app.post('/api/register', async (req, res) => {
  const { username, password: plainPassword } = req.body;

  if (!username || typeof username !== 'string') {
    return res.json({ status: 'error', error: 'Invalid username' });
  }

  if (!plainPassword || typeof plainPassword !== 'string') {
    return res.json({ status: 'error', error: 'Invalid password' });
  }

  if (plainPassword.length < 6) {
    return res.json({
      status: 'error',
      error: 'Password too small. Should be at least 8 characters',
    });
  }

  const password = await bcrypt.hash(plainPassword, 8);

  try {
    const response = await User.create({
      username,
      password,
    });
    console.log(response);
  } catch (error) {
    if (error.code === 11000) {
      return res.json({ status: 'error', error: 'Username alredy in use' });
    } else {
      throw error;
    }
  }

  res.json({ status: 'ok' });
});

app.listen(port, () => console.log(`Example app listening on port port!`));

//
