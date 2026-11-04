import { Router } from 'express';
import { createHash } from 'node:crypto';
import { createAuthController } from '../controllers/authController.js';

const normalizeEmail = value => typeof value === 'string' ? value.trim().toLowerCase() : '';

export function createAuthRoutes(dependencies) {
  const router = Router();
  const controller = createAuthController(dependencies);
  const { rateLimit, siteAuth } = dependencies;
  const ip = req => req.ip;
  const emailKey = req => createHash('sha256').update(normalizeEmail(req.body?.email)).digest('hex');

  router.post('/email-code/request',
    rateLimit({ windowMs: 15 * 60000, max: 5, keyFn: req => `elr:${ip(req)}:${emailKey(req)}` }),
    controller.requestLoginCode);
  router.post('/email-code/verify',
    rateLimit({ windowMs: 15 * 60000, max: 12, keyFn: req => `elv:${ip(req)}:${emailKey(req)}` }),
    controller.verifyLoginCode);
  router.post('/email-code/link/request', siteAuth,
    rateLimit({ windowMs: 15 * 60000, max: 4, keyFn: req => `elk:${ip(req)}:${req.accountId}` }),
    controller.requestEmailLinkCode);
  router.post('/email-code/link/verify', siteAuth,
    rateLimit({ windowMs: 15 * 60000, max: 10, keyFn: req => `elkv:${ip(req)}:${req.accountId}` }),
    controller.verifyEmailLinkCode);

  return router;
}
