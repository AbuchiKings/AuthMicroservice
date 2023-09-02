import dotenv from 'dotenv';
dotenv.config();

export const NODE_ENV = process.env.NODE_ENV;
export const CONTAINER = process.env.CONTAINER;
export const PORT = process.env.PORT;
export const WHITELIST = process.env.WHITELIST;


export const logDirectory = process.env.LOG_DIR;

export const redis = {
  host: process.env.REDIS_HOST || '',
  port: parseInt(process.env.REDIS_PORT || '0'),
  password: process.env.REDIS_PASSWORD || '',
};

/**
 * SECRET: secret for refresh token
 * SALT_ROUNDS: salt for password hash
 * REFRESH_EXPIRATION_TIMEFRAME: JWT expiry for refresh token
 * TOKEN_EXPIRATION_TIMEFRAME: JWT expiry for token
 * LOGINS_TRACKER_TIMEFRAME: expiry for set to track all user login instance
 * CACHED_TOKEN_EXPIRY: expiry for cached token key. required for token invalidation
 * CACHED_REFRESH_TOKEN_EXPIRY: expiry for chached refreshtoken key. required for refresh token invalidation
 */

export const SECRET = process.env.REFRESH_TOKEN_KEY;
export const SALT_ROUNDS = process.env.SALT_ROUNDS;
export const REFRESH_EXPIRATION_TIMEFRAME = process.env.REFRESH_EXPIRATION_TIMEFRAME || '2h';
export const TOKEN_EXPIRATION_TIMEFRAME = process.env.TOKEN_EXPIRATION_TIMEFRAME || '7d';
export const LOGINS_TRACKER_TIMEFRAME = process.env.LOGINS_TRACKER_TIMEFRAME || '3';
export const CACHED_TOKEN_EXPIRY = process.env.CACHED_TOKEN_EXPIRY || '2';
export const CACHED_REFRESH_TOKEN_EXPIRY = process.env.CACHED_REFRESH_TOKEN_EXPIRY || '7';
export const VERIFICATION_EXPIRY = process.env.CACHED_REFRESH_TOKEN_EXPIRY || '14d';
