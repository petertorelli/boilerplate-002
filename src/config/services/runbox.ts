import dotenv from 'dotenv';

dotenv.config();

export default {
  host: 'mail.runbox.com',
  port: 465,
  user: process.env.RUNBOX_USER,
  password: process.env.RUNBOX_PASSWORD,
};
