import nodemailer from 'nodemailer';

let transporter;
let transporterConfig;

function smtpConfig() {
  const host = process.env.SMTP_HOST || 'smtp.gmail.com';
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER || '';
  const pass = process.env.SMTP_PASS || '';
  const fromName = process.env.SMTP_FROM_NAME || 'Abyssal Nexoria';
  const fromEmail = process.env.SMTP_FROM_EMAIL || user;
  if (!host || port !== 587 || !user || !pass || !fromEmail) return null;
  return { host, port, user, pass, fromName, fromEmail };
}

export function isEmailConfigured() {
  return smtpConfig() !== null;
}

function getTransporter(config) {
  const fingerprint = `${config.host}:${config.port}:${config.user}:${config.fromEmail}`;
  if (!transporter || transporterConfig !== fingerprint) {
    transporter = nodemailer.createTransport({
      host: config.host,
      port: config.port,
      secure: false,
      requireTLS: true,
      authMethod: 'LOGIN',
      auth: { user: config.user, pass: config.pass },
      tls: { minVersion: 'TLSv1.2', rejectUnauthorized: true },
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 20000,
    });
    transporterConfig = fingerprint;
  }
  return transporter;
}

function safeSmtpError(error) {
  return {
    code: typeof error?.code === 'string' ? error.code.slice(0, 40) : 'SMTP_ERROR',
    responseCode: Number.isInteger(error?.responseCode) ? error.responseCode : undefined,
    command: typeof error?.command === 'string' ? error.command.slice(0, 40) : undefined,
  };
}

export async function sendEmail({ to, subject, html, text }) {
  const config = smtpConfig();
  if (!config) throw new Error('smtp_not_configured');
  try {
    await getTransporter(config).sendMail({
      from: { name: config.fromName, address: config.fromEmail },
      to,
      subject,
      html,
      text,
    });
  } catch (error) {
    console.error('[email] delivery failed', JSON.stringify(safeSmtpError(error)));
    throw new Error('email_delivery_failed');
  }
}

export async function verifyEmailTransport() {
  const config = smtpConfig();
  if (!config) return { configured: false, verified: false };
  try {
    await getTransporter(config).verify();
    console.info('[email] SMTP connection verified');
    return { configured: true, verified: true };
  } catch (error) {
    console.warn('[email] SMTP connection unavailable', JSON.stringify(safeSmtpError(error)));
    return { configured: true, verified: false };
  }
}
