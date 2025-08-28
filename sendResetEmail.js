const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') }); // ✅ 加這個

const nodemailer = require('nodemailer');
const { google } = require('googleapis');

const oAuth2Client = new google.auth.OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  process.env.REDIRECT_URI
);

oAuth2Client.setCredentials({ refresh_token: process.env.REFRESH_TOKEN });

async function sendResetEmail(to, resetLink) {
  const accessToken = await oAuth2Client.getAccessToken();

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      type: 'OAuth2',
      user: process.env.EMAIL_USER,
      clientId: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      refreshToken: process.env.REFRESH_TOKEN,
      accessToken: accessToken.token
    },
    logger: true,
    debug: true
  });

  const mailOptions = {
    from: `FHIR App <${process.env.EMAIL_USER}>`,
    to,
    subject: '重設密碼連結',
    html: `<p>請點選下方連結進行密碼重設：</p><a href="${resetLink}">${resetLink}</a>`
  };

  const result = await transporter.sendMail(mailOptions);
  return result;
}

module.exports = sendResetEmail;
