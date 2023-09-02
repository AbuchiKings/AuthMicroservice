import { Router, Request, RequestHandler, NextFunction } from 'express';

export interface UserInterface {
    id: number;
    firstname?: string;
    lastname?: string;
    fullname?: string;
    password?: string
    email?: string
    role?: string
    phone?: string
    createdAt?: Date;
    expiresIn?: number;
    settings?:{twoFA?: boolean, gTwoFA: boolean},
    isVerified: boolean
    isActive: boolean
}

export interface ProtectedRequest extends Request {
    user: UserInterface;
    accessToken?: string;
    refreshKey?: string;
    refreshToken?: string;
    hash?: string;
    verificationRequired?: boolean;
    addToken?: boolean;
    decodedToken?: any;
    data?: any;
    message?: string;
}

export interface Tokens {
    accessToken: string;
    refreshToken: string;
}
