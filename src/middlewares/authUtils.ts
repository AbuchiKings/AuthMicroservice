import path from 'path';
import { promisify } from 'util';
import { readFile } from 'fs';

import { sign, verify } from 'jsonwebtoken';

import { InternalError, AuthFailureError, BadTokenError, TokenExpiredError } from '../utils/requestUtils/ApiError';
import { UserInterface } from '../interfaces/interfaces'
import { SECRET } from '../config';

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

export const signToken = async (payload: JwtPayload): Promise<string> => {
    const cert = await readPrivateKey();
    if (!cert) throw new InternalError('Token generation failed');
    // @ts-ignore
    return promisify(sign)({ ...payload }, cert, { algorithm: 'RS256' });
}

export const validateToken = async (token: string): Promise<JwtPayload> => {
    const cert = await readPublicKey();
    if (!cert) throw new InternalError('Unable to read key.');
    // @ts-ignore
    return promisify(verify)(token, cert);
}

export const signAccessToken = async (payload: JwtPayload): Promise<string> => {
    // @ts-ignore
    return promisify(sign)({ ...payload }, SECRET);
}

export const validateAccessToken = async (token: string): Promise<JwtPayload> => {
    // @ts-ignore
    return promisify(verify)(token, SECRET);
}


export class JwtPayload {
    aud: string;
    key?: string;
    hash?: string;
    role?: string;
    iss?: string;
    iat?: number;
    exp?: number;
    sub?: number;
    email: string


    constructor(sub: number, key: string, email: string) {
        this.iss = 'issuer';
        this.aud = 'access';
        this.iat = Math.floor(Date.now() / 1000);
        //this.exp = this.iat + 3 * 24 * 60 * 60;
        this.email = email
        this.key = key
        this.sub = sub
    }
}

export const createToken = async (user: UserInterface, accessTokenKey: string): Promise<string> => {
    const accessToken = await signToken(
        new JwtPayload(
            user.id,
            accessTokenKey,
            user.email || ''
        ),
    );

    if (!accessToken) throw new InternalError();
    return accessToken
};

export const getAccessToken = (authorization?: string) => {
    if (!authorization) throw new AuthFailureError('Missing Authorization Headers.');
    if (!authorization.startsWith('Bearer ')) throw new AuthFailureError('Invalid Authorization.');
    return authorization.split(' ')[1];
};

