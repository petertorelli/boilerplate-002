import express from 'express';
import {Request, Response, NextFunction as Next} from 'express';
import Debug from 'debug';
import jwt from 'jsonwebtoken';
import config from '@config';
import auth from '@models/auth';

const debug = Debug('backend:validate-user');

function checkJwt(req: Request, res: Response, next: Next) {
  debug('checkJwt');
  res.locals.validUser = false;
  if (req.session && req.session.token) {
    try {
      res.locals.token = jwt.verify(req.session.token, config.jwt.secret);
    } catch (error) {
      console.error(error);
    }
  }
  return next();
}

async function checkLoginToken(req: Request, res: Response, next: Next) {
  debug('checkLoginToken');
  if (res.locals && res.locals.token) {
    const username = res.locals.token.username;
    const login_token = res.locals.token.login_token;
    try {
      const user = await auth.validate_login(username, login_token);
      res.locals.validUser = true;
      res.locals.user = user;
    } catch (error) {
      console.error(error);
    }
  }
  return next();
}

export default express.Router().use(checkJwt, checkLoginToken);
