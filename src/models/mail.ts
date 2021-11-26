import nodemailer from 'nodemailer';
import config from '@config';

async function send(envelope: nodemailer.SendMailOptions) {
  const transport = {
    host: config.mail.host,
    port: config.mail.port,
    secure: true,
    auth: {
      user: config.mail.user,
      pass: config.mail.password,
    },
  };
  return new Promise<void>((resolve, reject) => {
    const transporter = nodemailer.createTransport(transport);
    transporter.sendMail(envelope, (error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

export default {
  send,
};
