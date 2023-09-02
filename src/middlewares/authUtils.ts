import path from 'path';
import { promisify } from 'util';
import { readFile } from 'fs';

import { sign, verify } from 'jsonwebtoken';

import { InternalError, AuthFailureError, BadTokenError, TokenExpiredError } from '../utils/requestUtils/ApiError';
import { UserInterface, Tokens, ProtectedRequest } from '../interfaces/interfaces'
import { SECRET, TOKEN_EXPIRATION_TIMEFRAME, REFRESH_EXPIRATION_TIMEFRAME } from '../config';

const readPublicKey = async (): Promise<string> => {
    return promisify(readFile)(
        path.join(__dirname, '../pem/public.pem'),
        'utf8',
    );
}

const readPrivateKey = async (): Promise<string> => {
    return promisify(readFile)(
        path.join(__dirname, '../pem/private.pem'),
        'utf8',
    );
}

export const signToken = async (payload: JwtPayload, expiresIn = TOKEN_EXPIRATION_TIMEFRAME): Promise<string> => {
    const cert = await readPrivateKey();
    if (!cert) throw new InternalError('Token generation failed');
    // @ts-ignore
    return promisify(sign)({ ...payload }, cert, { algorithm: 'RS256', expiresIn });
}

export const validateToken = async (token: string): Promise<JwtPayload> => {
    const cert = await readPublicKey();
    if (!cert) throw new InternalError('Unable to read key.');
    // @ts-ignore
    return promisify(verify)(token, cert);
}

export const signRefreshToken = async (payload: JwtPayload): Promise<string> => {
    // @ts-ignore
    return promisify(sign)({ ...payload }, SECRET, { expiresIn: REFRESH_EXPIRATION_TIMEFRAME });
}

export const validateRefreshToken = async (token: string): Promise<JwtPayload> => {
    // @ts-ignore
    return promisify(verify)(token, SECRET);
}

export const decodeJwt = (token: string, secret = SECRET): Promise<JwtPayload> => {

    const cert = readPublicKey();
    if (!cert) throw new InternalError('Unable to read key.');
    // @ts-ignore
    return promisify(verify)(token, secret, { ignoreExpiration: true });
}


export class JwtPayload {
    aud: string;
    hash?: string;
    key?: string;
    role?: string;
    iss?: string;
    sub: number;
    email: string


    constructor(sub: number, hash: string, email?: string, key?: string) {
        this.iss = 'issuer';
        this.aud = 'access';
        email ? this.email : {}
        this.hash = hash
        this.key = key
        this.sub = sub
    }
}

export const createTokens = async (user: UserInterface, hash: string, refreshTokenKey: string): Promise<Tokens> => {
    const [accessToken, refreshToken] = await Promise.all([
        signToken(
            new JwtPayload(
                user.id,
                hash,
                user.email || ''
            ),),
        signRefreshToken(
            new JwtPayload(
                user.id,
                hash,
                user.email || '',
                refreshTokenKey
            ),)
    ])

    if (!accessToken || refreshToken) throw new InternalError();
    return { accessToken, refreshToken }
};

export const getAccessToken = (authorization?: string) => {
    if (!authorization) throw new AuthFailureError('Missing Authorization Headers.');
    if (!authorization.startsWith('Bearer ')) throw new AuthFailureError('Invalid Authorization.');
    return authorization.split(' ')[1];
};



export const genVerificationCode = async(user: UserInterface) => {
/***
 * creates  verification code and sends to user via mail
 *  */   
 return;
}