/* Copyright (C) Peter Torelli <peter.j.torelli@gmail.com> */
import mysql from './services/mysql';
import jwt from './services/jwt';
import runbox from './services/runbox';

export default {
  mysql,
  jwt,
  mail: runbox,
};
