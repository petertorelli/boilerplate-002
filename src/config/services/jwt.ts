/* Copyright (C) Peter Torelli <peter.j.torelli@gmail.com> */
import crypto from 'crypto';

// Force the secret to reset every server reboot
export default {
  secret: crypto.randomBytes(16).toString('hex'),
};
