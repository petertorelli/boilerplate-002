/* Copyright (C) Peter Torelli <peter.j.torelli@gmail.com> */
import dotenv from 'dotenv';

dotenv.config();

export default {
  host: 'localhost',
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  port: 3306,
  database: process.env.MYSQL_DATABASE,
};
