/* Copyright (C) Peter Torelli <peter.j.torelli@gmail.com> */
import path from 'path';
import express from 'express';
import auth from '@models/auth';

const router = express.Router();

const pugSignUp = path.join(__dirname, 'pug', 'signup');
const pugConfirm = path.join(__dirname, 'pug', 'confirm');
const pugResend = path.join(__dirname, 'pug', 'resend');

router.get('/signup', (req, res) => {
  return res.render(pugSignUp);
});

router.post('/signup', async (req, res) => {
  try {
    await auth.signup(req.body.email, req.body.password, req.body.repassword);
  } catch (error) {
    let code = 406;
    const args = {
      error: null as string | null,
      serverClass: 'alert alert-danger',
      // repopulate the form on error reload
      email: req.body.email as string,
      password: req.body.password as string,
      repassword: req.body.repassword as string,
    };
    if (error instanceof auth.ClientError) {
      args.error = error.message;
    } else {
      args.error = 'There was an error signing up.';
      code = 500;
      console.error(error);
    }
    // OK to render to same page on post return. Is it?
    return res.status(code).render(pugSignUp, args);
  }
  return res.redirect('confirm-sent');
});

router.get('/confirm-sent', (req, res) => {
  res.render(pugConfirm);
});

router.get('/confirm/:token', async (req, res) => {
  try {
    await auth.confirm(req.params.token);
  } catch (error) {
    let code = 406;
    const args = {
      error: null as string | null,
      serverClass: 'alert alert-danger',
    };
    if (error instanceof auth.ClientError) {
      args.error = error.message;
    } else {
      args.error = 'There was an error confirming your account.';
      code = 500;
      console.error(error);
    }
    // OK to render to same page on post return. Is it?
    return res.status(code).render(pugConfirm, args);
  }
  // Weird. When there's a parameter we need to move up the hierarchy.
  return res.redirect('../signin');
});

router.get('/resend', (req, res) => {
  return res.render(pugResend);
});

// HUh, forms can only get/post. Fneh.
router.post('/resend', async (req, res) => {
  try {
    await auth.resend(req.body.email);
  } catch (error) {
    let code = 406;
    const args = {
      error: null as string | null,
      serverClass: 'alert alert-danger',
    };
    if (error instanceof auth.ClientError) {
      args.error = error.message;
    } else {
      args.error = 'There was an error resending your confirmation email.';
      code = 500;
      console.error(error);
    }
    // OK to render to same page on post return. Is it?
    return res.status(code).render(pugResend, args);
  }
  return res.send('OK');
});

export default router;
