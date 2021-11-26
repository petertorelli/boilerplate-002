import express from 'express';

import signup from './funcs/signup';
import signin from './funcs/signin';
import signout from './funcs/signout';
import change from './funcs/change';

export default express
  .Router()
  .use(signup)
  .use(signin)
  .use(signout)
  .use(change);
