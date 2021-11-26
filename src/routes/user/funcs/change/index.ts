/* Copyright (C) Peter Torelli <peter.j.torelli@gmail.com> */
import path from 'path';
import express from 'express';
import auth from '@models/auth';
import jwt from 'jsonwebtoken';
import config from '@config';
import validateUser from '@middleware/validate-user';

const router = express.Router();

const pugReset = path.join(__dirname, 'pug', 'reset');
const pugResetSent = path.join(__dirname, 'pug', 'reset-sent');
const pugResetError = path.join(__dirname, 'pug', 'reset-error');
const pugChange = path.join(__dirname, 'pug', 'change');
const pugChangeSuccess = path.join(__dirname, 'pug', 'change-success');

router.get('/reset', (req, res) => {
  return res.render(pugReset);
});

router.post('/reset', async (req, res) => {
  try {
    await auth.reset(req.body.email);
  } catch (error) {
    let code = 406;
    const args = {
      error: null as string | null,
      serverClass: 'alert alert-danger',
      email: req.body.email,
    };
    if (error instanceof auth.ClientError) {
      args.error = error.message;
    } else {
      args.error = 'There was an error sending your password-reset email.';
      code = 500;
      console.error(error);
    }
    // OK to render to same page on post return. Is it?
    return res.status(code).render(pugReset, args);
  }
  return res.redirect('reset-sent');
});

router.get('/reset-sent', (req, res) => {
  return res.render(pugResetSent);
});

// Note that password-reset also serves as confirmation of the email.
router.get('/reset/:token', async (req, res) => {
  try {
    const user = await auth.signin_token(req.params.token);
    const payload = {
      username: user.username,
      login_token: user.login_token,
    };
    const token = jwt.sign(payload, config.jwt.secret, {expiresIn: '14d'});
    req.session = {token};
  } catch (error) {
    let code = 406;
    const args = {
      error: null as string | null,
      serverClass: 'alert alert-danger',
    };
    if (error instanceof auth.ClientError) {
      args.error = error.message;
    } else {
      args.error = 'There was an error authorizing the password reset.';
      code = 500;
      console.error(error);
    }
    // Don't redirect (keep URL bar), but render an error with a link.
    return res.status(code).render(pugResetError, args);
  }
  return res.redirect('../change');
});

router.get('/change', validateUser, (req, res) => {
  if (res.locals.validUser) {
    return res.render(pugChange);
  } else {
    req.flash('nexturl', req.originalUrl);
    return res.redirect('signin');
  }
});

router.post('/change', validateUser, async (req, res) => {
  if (res.locals.validUser == false) {
    return res.status(500).send('User not logged in.');
  }
  try {
    await auth.change(
      res.locals.user.username,
      req.body.password,
      req.body.repassword
    );
  } catch (error) {
    let code = 406;
    const args = {
      error: null as string | null,
      serverClass: 'alert alert-danger',
    };
    if (error instanceof auth.ClientError) {
      args.error = error.message;
    } else {
      args.error = 'There was an error trying to change your password.';
      code = 500;
      console.error(error);
    }
    return res.status(code).render(pugChange, args);
  }
  return res.redirect('change-success');
});

router.get('/change-success', (req, res) => {
  res.render(pugChangeSuccess);
});

export default router;
