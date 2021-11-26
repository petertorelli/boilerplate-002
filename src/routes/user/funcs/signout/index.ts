import express from 'express';

const router = express.Router();

router.get('/signout', (req, res) => {
  res.clearCookie('sitecook');
  res.clearCookie('sitecook.sig');
  res.redirect('/');
});

export default router;
