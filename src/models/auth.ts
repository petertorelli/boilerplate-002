/* Copyright (C) Peter Torelli <peter.j.torelli@gmail.com> */
import Debug from 'debug';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import db from './db';
import mail from './mail';
import {RowDataPacket} from 'mysql2';
import dotenv from 'dotenv';

dotenv.config();

// These errors will be sent back to the User, so be careful.
class ClientError extends Error {
  constructor(message: string) {
    super(message);
  }
}

const REGEX_IS_ASCII_PRINT = new RegExp(/^[\x20-\x7e]+$/);
const debug = Debug('backend:auth');
const SALT_ROUNDS = 10;

///
///
///https://clients.websavers.ca/whmcs/knowledgebase/220/Gmail-says-it-couldnandsharp039t-verify-that-you-actually-sent-this-message-and-not-a-spammer.html
///
//

async function mailConfirmationNotice(email: string, token: string) {
  debug('mailConfirmationNotice(', email, ', ', token, ')');
  const url = process.env.SITE_URL + '/user/confirm/' + token;
  await mail.send({
    subject: `Confirm your account at ${process.env.DOMAIN}`,
    to: email,
    from: `"${process.env.CONTACT_EMAIL}" <${process.env.CONTACT_EMAIL}>`,
    text:
      'Someone used this email to create an account at ' +
      `${process.env.DOMAIN}.\n` +
      'Follow this link to confirm your account within one hour:\n' +
      url +
      '\n' +
      "...or simply disregard this email if it wasn't you.\n\n",
  });
}

async function mailPasswordResetNotice(email: string, token: string) {
  debug('mailPasswordResetNotice(', email, token, ')');
  const url = process.env.SITE_URL + '/user/reset/' + token;
  return mail.send({
    subject: `Reset your password at ${process.env.DOMAIN}`,
    to: email,
    from: `"${process.env.CONTACT_EMAIL}" <${process.env.CONTACT_EMAIL}>`,
    text:
      'Someone used this email to reset their password at ' +
      `${process.env.DOMAIN}.\n` +
      'Follow this link to reset it with within one hour:\n' +
      url +
      '\n' +
      "...or simply disregard this email if it wasn't you.\n\n",
  });
}

async function sqlInsertNewUser(email: string, password: string) {
  debug('sqlInsertNewUser(', email, ',', password, ')');
  // This is where `username` is first created.
  const username = email.toLowerCase();
  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  const params = [username, email, hash];
  const sql =
    'INSERT INTO users ' +
    '(username, email, password, active, security_level) ' +
    'VALUES (?, ?, ?, 0, 0)';
  await db.execute({sql}, params).catch((error) => {
    if (error.code == 'ER_DUP_ENTRY') {
      throw new ClientError('That email is already in use.');
    } else {
      throw error;
    }
  });
}

async function sqlSelectUserByEmail(email: string) {
  debug('sqlSelectUserByEmail(', email, ')');
  const params = [email];
  const sql = 'SELECT * FROM users WHERE email=?';
  const [results] = await db.query<RowDataPacket[]>({sql}, params);
  if (results.length == 0) {
    throw new ClientError('User not found.');
  }
  if (results.length > 1) {
    // Not a public error!
    throw new Error('Expected only one username, got multiple.');
  }
  // Explicitly accessing & typing the results of the query to force errors.
  return {
    username: results[0].username as string,
    password_hash: results[0].password as string,
    active: results[0].active as number,
    security_level: results[0].security_level as number,
    login_token: results[0].login_token as string,
    auth_token: results[0].auth_token as string,
    email: results[0].email as string,
  };
}

async function sqlSelectUserByAuthToken(token: string) {
  debug('sqlSelectUserByAuthToken(', token, ')');
  if (!token) {
    throw new Error('No authorization token provided for user select.');
  }
  const date = token.slice(32);
  const tokenBirth = new Date(parseInt(date, 16)).getTime();
  const now = Date.now();
  const diffMsec: number = now - tokenBirth;
  const expireMsec = 1 * 60 * 60 * 1000;
  if (diffMsec > expireMsec) {
    throw new ClientError('Authorization token has expired.');
  }
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  const params = [hash];
  // Possibly collate utf8mb4 on token fields that need be byte-exact?
  const sql = 'SELECT * FROM users WHERE auth_token = BINARY ?';
  const [results] = await db.query<RowDataPacket[]>({sql}, params);
  if (results.length !== 1) {
    throw new ClientError('Authorization token is invalid.');
  }
  // Explicitly accessing & typing the results of the query to force errors.
  return {
    username: results[0].username as string,
    password_hash: results[0].password as string,
    active: results[0].active as number,
    security_level: results[0].security_level as number,
    login_token: results[0].login_token as string,
    auth_token: results[0].auth_token as string,
    email: results[0].email as string,
  };
}

async function sqlCreateAuthToken(username: string) {
  debug('sqlCreateAuthToken(', username, ')');
  const randomBytes = crypto.randomBytes(16).toString('hex');
  const now = Date.now().toString(16);
  const prehash = randomBytes + now;
  const token = crypto.createHash('sha256').update(prehash).digest('hex');
  const params = [token, username];
  const sql = 'UPDATE users SET auth_token=? WHERE username=?';
  await db.execute({sql}, params);
  return prehash; // sic. we are sending random bytes plus date!
}

async function sqlClearAuthToken(username: string) {
  debug('sqlClearAuthToken(', username, ')');
  const params = [username];
  const sql = 'UPDATE users SET auth_token=NULL WHERE username=?';
  await db.execute({sql}, params);
}

async function sqlCreateLoginToken(username: string) {
  debug('sqlCreateLoginToken(', username, ')');
  const randomBytes = crypto.randomBytes(32).toString('hex');
  const body = randomBytes + username;
  const token = crypto.createHash('sha256').update(body).digest('hex');
  const params = [token, username];
  const sql = 'UPDATE users SET login_token=? WHERE username=?';
  await db.execute({sql}, params);
}

async function sqlClearLoginToken(username: string, login_token: string) {
  debug('sqlClearLoginToken(', username, ', ', login_token, ')');
  const params = [username, login_token];
  const sql =
    'UPDATE users SET login_token=NULL WHERE username=? and login_token=?';
  await db.execute({sql}, params);
}

async function sqlActivateAccount(username: string) {
  debug('sqlActivateAccount(', username, ')');
  const params = [username];
  const sql = 'UPDATE users SET active=1 WHERE username=?';
  await db.execute({sql}, params);
}

async function sqlChangePassword(username: string, hash: string) {
  debug('sqlChangePassword(', username, ')');
  const params = [hash, username];
  const sql = 'UPDATE users SET password=? WHERE username=?';
  await db.execute({sql}, params);
}

async function signup(email: string, password: string, repassword: string) {
  debug('signup(', email, ',', password, ')');
  if (!email.match(REGEX_IS_ASCII_PRINT)) {
    throw new ClientError('Invalid email address.');
  }
  if (!password.match(REGEX_IS_ASCII_PRINT)) {
    throw new ClientError('Invalid password.');
  }
  if (password !== repassword) {
    throw new ClientError('Passwords do not match.');
  }
  await sqlInsertNewUser(email, password);
  const user = await sqlSelectUserByEmail(email);
  const token = await sqlCreateAuthToken(user.username);
  await mailConfirmationNotice(email, token);
}

async function signin_password(email: string, plaintextpw: string) {
  debug('signin_password(', email, ', <plaintext_password>)');
  const user = await sqlSelectUserByEmail(email);
  const pass = await bcrypt.compare(plaintextpw, user.password_hash);
  if (pass == false) {
    throw new ClientError('The password is incorrect.');
  }
  if (user.active == 0) {
    throw new ClientError('Account has not been activated.');
  }
  if (user.security_level == 0) {
    throw new ClientError('Active account does not have permissions.');
  }
  await sqlCreateLoginToken(user.username);
  return await sqlSelectUserByEmail(user.email); // new token, select again
}

async function signin_token(token: string) {
  debug('signin_token(', token, ')');
  const user = await sqlSelectUserByAuthToken(token);
  await sqlClearAuthToken(user.username);
  await sqlCreateLoginToken(user.username);
  return await sqlSelectUserByEmail(user.email); // new token, select again
}

// Require a login_token so that only the signed-in user can sign out.
async function signout(username: string, login_token: string) {
  debug('signout(', username, ', ', login_token, ')');
  await sqlClearLoginToken(username, login_token);
}

async function confirm(auth_token: string) {
  debug('confirm(', auth_token, ')');
  const user = await sqlSelectUserByAuthToken(auth_token);
  await sqlClearAuthToken(user.username);
  await sqlActivateAccount(user.username);
}

async function resend(email: string) {
  debug('resend(', email, ')');
  if (!email.match(REGEX_IS_ASCII_PRINT)) {
    throw new ClientError('Invalid email address.');
  }
  const user = await sqlSelectUserByEmail(email);
  const token = await sqlCreateAuthToken(user.username);
  await mailConfirmationNotice(email, token);
}

async function reset(email: string) {
  debug('reset(', email, ')');
  const user = await sqlSelectUserByEmail(email);
  const token = await sqlCreateAuthToken(user.username);
  await mailPasswordResetNotice(email, token);
}

async function change(username: string, password: string, repassword: string) {
  debug('change()');
  if (!password.match(REGEX_IS_ASCII_PRINT)) {
    throw new ClientError('Invalid password.');
  }
  if (password !== repassword) {
    throw new ClientError('Passwords do not match.');
  }
  const user = await sqlSelectUserByEmail(username);
  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  await sqlChangePassword(user.username, hash);
}

async function validate_login(username: string, login_token: string) {
  const user = await sqlSelectUserByEmail(username);
  if (user.login_token == null) {
    throw new Error('User not logged in');
  }
  if (user.login_token != login_token) {
    throw new Error('Login tokens do not match');
  }
  return user;
}

export default {
  signin_password,
  signin_token,
  signup,
  signout,
  confirm,
  resend,
  reset,
  change,
  validate_login,

  ClientError,
};
