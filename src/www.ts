import path from 'path';
import express from 'express';
import api from './api';

const app = express();

app.use(api);
app.set('view engine', 'pug');
app.locals.basedir = path.join(process.cwd(), 'views');
app.listen(3000, () => console.log('API listening on 3000'));
