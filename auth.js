const crypto = require('node:crypto');

const SCRYPT_KEY_LENGTH = 64;

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, SCRYPT_KEY_LENGTH);
  return `${salt}:${derivedKey.toString('hex')}`;
}

function verifyPassword(password, storedHash) {
  const [salt, hashHex] = storedHash.split(':');
  if (!salt || !hashHex) return false;
  const storedBuffer = Buffer.from(hashHex, 'hex');
  const suppliedBuffer = crypto.scryptSync(password, salt, SCRYPT_KEY_LENGTH);
  if (storedBuffer.length !== suppliedBuffer.length) return false;
  return crypto.timingSafeEqual(storedBuffer, suppliedBuffer);
}

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'not authenticated' });
  }
  next();
}

module.exports = { hashPassword, verifyPassword, requireAuth };
