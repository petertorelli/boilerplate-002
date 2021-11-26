import path from 'path';
import express from 'express';
import auth from '@models/auth';
import jwt from 'jsonwebtoken';
import config from '@config';

const router = express.Router();

const pugSignIn = path.join(__dirname, 'pug', 'signin');

router.get('/signin', (req, res) => {
  const nexturl = req.flash('nexturl');
  return res.render(pugSignIn, {
    nexturl: nexturl.length > 0 ? nexturl[0] : '/',
  });
});

router.post('/signin', async (req, res) => {
  try {
    const user = await auth.signin_password(req.body.email, req.body.password);
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
      // repopulate the form on error reload
      email: req.body.email as string,
      password: req.body.password as string,
      repassword: req.body.repassword as string,
    };
    if (error instanceof auth.ClientError) {
      args.error = error.message;
    } else {
      args.error = 'There was an error signing in.';
      code = 500;
      console.error(error);
    }
    // OK to render to same page on post return. Is it?
    return res.status(code).render(pugSignIn, args);
  }
  return res.redirect(req.body.nexturl || '/');
});

export default router;
