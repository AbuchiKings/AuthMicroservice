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

export const SECRET = process.env.REFRESH_TOKEN_KEY;
export const ITERATIONS = process.env.ITERATIONS;
export const HASH_BYTES = process.env.HASH_BYTES;
export const SALT_BYTES = process.env.SALT_BYTES;
export const SALT_ROUNDS = process.env.SALT_ROUNDS;
export const REFRESH_EXPIRATION_TIMEFRAME = process.env.REFRESH_EXPIRATION_TIMEFRAME || '2h';
export const TOKEN_EXPIRATION_TIMEFRAME = process.env.TOKEN_EXPIRATION_TIMEFRAME || '7d';
