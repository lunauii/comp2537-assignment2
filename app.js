import express from 'express';
import session from 'express-session';
import path from 'path';
import MongoStore from 'connect-mongo';
import { MongoClient } from 'mongodb';
import bcrypt from 'bcrypt'
import {fileURLToPath} from 'url';
import Joi from 'joi';
import crypto from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

import "dotenv/config.js";

const mongoDBHost = process.env.MONGODB_HOST;
const mongoDBUser = process.env.MONGODB_USER;
const mongoDBPassword = process.env.MONGODB_PASSWORD;
const mongoDBDatabase = process.env.MONGODB_DATABASE;

const mongoUrl = `mongodb+srv://${mongoDBUser}:${mongoDBPassword}@${mongoDBHost}/${mongoDBDatabase}`

app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    store: MongoStore.create({
        mongoUrl: mongoUrl,
        collectionName: 'sessions',
        ttl: 60 * 60,
        crypto: {
            secret: process.env.MONGODB_SESSION_SECRET
        }
    }),
    resave: true,
    saveUninitialized: false,
    cookie: {
        secure: false,
        maxAge: 60 * 60 * 1000 // 1 hour
    }
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const client = new MongoClient(mongoUrl);

let db;
let userCollection;
let conn;

(async () => {
    try {
        conn = await client.connect();
        db = client.db();
        userCollection = db.collection('users');
        console.log('Connected to MongoDB');
    } catch (err) {
        console.error('MongoDB connection error:', err);
    }
})();

app.get('/', (req, res) => {
    if (req.session.user) {
        res.render('homeLoggedIn', 
            {
                user: req.session.user 
            }
        );
    } else {
        res.render('homeNotLoggedIn');
    }
});

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.post('/signupSubmit', async (req, res) => {
    const schema = Joi.object({
        name: Joi.string().required(),
        email: Joi.string().email().required(),
        password: Joi.string().required()
    });

    const validationResult = schema.validate(req.body);

    if (validationResult.error) {
        const errorMessage = validationResult.error.details[0].message;
        return res.render('authSignupError', { error: errorMessage });
    }

    try {
        const existingUser = await userCollection.findOne({ email: req.body.email });

        if (existingUser) {
            return res.render('authSignupError', { error: 'Email already in use' });
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 10);

        const newUser = {
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword,
        };

        await userCollection.insertOne(newUser);

        req.session.user = {
            name: req.body.name
        };

        res.redirect('/members');

    } catch (err) {
        console.error(err);
        res.render('authSignupError', { error: 'An error occurred during signup' });
    }
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/loginSubmit', async (req, res) => {
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().required()
    });

    const validationResult = schema.validate(req.body);
    if (validationResult.error) {
        return res.render('authLoginError', { error: 'Invalid email/password combination' });
    }

    try {
        const user = await userCollection.findOne({ email: req.body.email });
        if (!user) {
            return res.render('authLoginError', { error: 'Invalid email/password combination' });
        }

        const passwordMatch = await bcrypt.compare(req.body.password, user.password);
        if (!passwordMatch) {
            return res.render('authLoginError', { error: 'Invalid email/password combination' });
        }

        req.session.user = {
            name: user.name
        };

        res.redirect('/members');
    } catch (err) {
        console.error(err);
        res.render('authLoginError', { error: 'An error occurred during login' });
    }
});

app.get('/members', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/');
    }

    const images = ['image1.png', 'image2.png', 'image3.png'];
    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.render('members', { 
        user: req.session.user,
        image: randomImage
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
        }
        res.redirect('/');
    });
});

app.use(function (req, res) {
    res.status(404);
    res.send("Page not found - 404");
});

const port = 3000;

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
