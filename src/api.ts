import express from 'express';
import cookieSession from 'cookie-session';
import morgan from 'morgan';
import flash from 'connect-flash';
import routerUser from './routes/user';

import dotenv from 'dotenv';

dotenv.config();

const router = express.Router();
const key1 = process.env.KEY1;
const key2 = process.env.KEY2;

if (key1 == undefined || key2 == undefined) {
  console.error('Key1 or Key2 is undefined');
  process.exit();
}

const session = cookieSession({
  name: 'sitecook',
  secure: process.env.NODE_ENV === 'development' ? false : true,
  keys: [key1, key2],
  httpOnly: true,
  sameSite: true,
  expires: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
});

router.use(morgan('dev'));
router.use(express.json());
router.use(express.urlencoded({extended: true}));
router.use(session);
router.use(flash());
router.use('/user', routerUser);
router.use((req, res) => {
  res.status(404).send(`URL ${req.originalUrl} not found.`);
});

export default router;
