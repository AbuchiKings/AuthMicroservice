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
}

export interface ProtectedRequest extends Request {
    user: UserInterface;
    accessToken?: string;
    refreshToken?: string;
    hash?: string;
    decodedToken?: any;
}

export type RequestFunction = (req: Request | ProtectedRequest, res: Response, next: NextFunction) => void;