import crypto from 'crypto';
import { promisify } from 'util';

import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction, Router, CookieOptions } from 'express';

import { InternalError, AuthFailureError, ForbiddenError } from '../utils/requestUtils/ApiError';
import { ProtectedRequest, UserInterface } from '../interfaces/interfaces'
import { SuccessResponse } from '../utils/requestUtils/ApiResponse';
import { RefreshRepository, UserRepository } from '../services/repository';

import { genVerificationCode, getAccessToken, signToken, validateToken, JwtPayload, createTokens, validateRefreshToken, decodeJwt } from './authUtils';
import { rdGet, rdSet, rdSadd, rdSrem, rdExp, rdDel, rdSmem, rdHget, rdHset } from '../utils/cache';
//import { readPublicKey, readPrivateKey } from './authUtils';
//import { taskQueue } from '../jobs/jobs';
import {
    SECRET, CACHED_REFRESH_TOKEN_EXPIRY, CACHED_TOKEN_EXPIRY, SALT_ROUNDS, LOGINS_TRACKER_TIMEFRAME,
    VERIFICATION_EXPIRY
} from '../config';

//Router().post('/', Auth.verifyToken)

export default class Auth {
    public static async verifyToken(req: ProtectedRequest, res: Response, next: NextFunction) {
        try {
            const token = getAccessToken(req.headers.authorization);
            if (!token) throw new AuthFailureError('Unauthorised. Please login with your details');

            const decodedToken = await validateToken(token);

            const { sub, role, hash }: JwtPayload = decodedToken;

            let userString = await rdGet(`${role}-${sub}-${hash}`);
            console.log(userString); // eslint-disable-line

            if (!userString) {
                throw new AuthFailureError('Unauthorised. Please login with your details.');
            }

            let user: UserInterface = JSON.parse(userString);

            if (user.expiresIn && user.expiresIn < Date.now()) {
                throw new AuthFailureError('Unauthorised. Please login with your details.');
            }

            const currentUser = await UserRepository.findOne({ where: { id: decodedToken.sub, isActive: true } })
            if (!currentUser) throw new ForbiddenError('User does not exist');

            req.user = currentUser;
            req.decodedToken = decodedToken;
            return next();
        } catch (error: any) {
            if (error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
                error.message = 'Unauthorised. Please login with your details';
            }
            return next(error);
        }
    }

    public static async signToken(req: ProtectedRequest, res: Response, next: NextFunction) {
        try {

            let { id, email, role } = req.user;
            const hash = crypto.randomBytes(20).toString('hex');
            const refreshKey = req.refreshKey || '';

            const { accessToken, refreshToken } = await createTokens(req.user, hash, refreshKey);

            await Promise.all([
                rdSet(
                    `${role}-${id}-${hash}`,
                    JSON.stringify({ id, email, role, expiresIn: Date.now() + 2 * 3600 * 1000 }),
                ),
                rdSadd(`${role}-${id}`, `${hash}`),
                rdExp(`${role}-${id}-${hash}`, +CACHED_TOKEN_EXPIRY * 3600),
                rdExp(`${role}-${id}`, +LOGINS_TRACKER_TIMEFRAME * 3600),
            ]);

            req.refreshToken = refreshToken;
            req.accessToken = accessToken;
            req.hash = hash;
            return next();
        } catch (error) {
            next(error);
        }
    }

    public static addToken(req: ProtectedRequest, res: Response, next: NextFunction) {
        const accessToken = req.accessToken;
        const refreshToken = req.refreshToken;

        req.data = {
            accessToken,
            refreshToken,
            ...req.user,
            verificationRequired: req.verificationRequired,
        };
        return next();
    }

    public static async checkIfVerificationIsRequired(req: ProtectedRequest, res: Response, next: NextFunction) {
        if (!req.user?.settings?.twoFA) return next();

        let token;
        if (req.cookies && req.cookies.vck) {
            token = req.cookies.vck;
        }
        if (!token) {
            req.verificationRequired = true;
            req.user.settings.gTwoFA ? {} : await genVerificationCode(req.user);
            return next();
        }

        let decodedToken;
        try {
            decodedToken = await validateToken(token);
        } catch (error) {
            req.user.settings.gTwoFA ? {} : await genVerificationCode(req.user);
            req.verificationRequired = true;
            return next();
        }
        if (!decodedToken) return next();

        if (`${decodedToken.sub}` !== `${req.user.id}`) {
            req.user.settings.gTwoFA ? {} : await genVerificationCode(req.user);
            req.verificationRequired = true;
            return next();
        }
        req.addToken = true;
        return next();
    }

    public static async addVerificationCookie(req: ProtectedRequest, res: Response, next: NextFunction) {
        try {
            if (!req.addToken) {
                const message = req.message || 'Successfully logged in.';
                return new SuccessResponse(message, null, 0).send(res);
            }
            let hash = req.hash || req.decodedToken?.hash;
            const { id } = req.user;

            const vck = await signToken(new JwtPayload(id, hash), VERIFICATION_EXPIRY)

            const cookieOptions: CookieOptions = {
                httpOnly: true,
                expires: new Date(Date.now() + parseInt(VERIFICATION_EXPIRY.split('h')[0]) * 1000 * 60 * 60 * 24),
                sameSite: 'none',
                secure: process.env.NODE_ENV !== 'development' ? true : false,
                domain: process.env.NODE_ENV !== 'development' ? process.env.ORIGIN : undefined,
            };
            res.cookie('vck', vck, cookieOptions);

            let message = 'Successfully verified.';
            req.message ? (message = req.message) : {};
            const data = req.data || null;
            return new SuccessResponse(message, data, 1).send(res);
        } catch (error) {
            return next(error);
        }
    }

    public static async checkIfUserIs2faVerified(req: ProtectedRequest, res: Response, next: NextFunction) {
        try {
            if (!req.user?.settings?.twoFA) return next();
            let token;
            if (req.cookies && req.cookies.vck) {
                token = req.cookies.vck;
            }
            if (!token) throw new ForbiddenError('Verification Required.'); // edit message with care

            const decodedToken = await validateToken(token);
            if (
                `${decodedToken.sub}` !== `${req.user.id}` ||
                `${decodedToken.hash}` !== `${req.decodedToken.hash}`
            ) {
                throw new ForbiddenError('Verification Required.');
            }
            return next();
        } catch (error: any) {
            if (['TokenExpiredError', 'JsonWebTokenError'].includes(error.name)) {
                let err = new ForbiddenError('Verification Required.');
                return next(err);
            }
            return next(error);
        }
    }

    public static checkIfUserIsVerified(req: ProtectedRequest, res: Response, next: NextFunction) {
        try {
            if (!req.user?.isVerified) {
                throw new ForbiddenError('Please verify your account to proceed.');
            }
            return next();
        } catch (error) {
            return next(error);
        }
    }

    public static async validateRefreshToken(req: ProtectedRequest, res: Response, next: NextFunction) {
        try {
            let token = req.headers['x- refresh-token'];

            if (!token || typeof token !== 'string') throw new AuthFailureError('Invalid credentials. Please login with your details.');

            const decodedToken = await validateRefreshToken(token);

            let authorization = getAccessToken(req.headers.authorization)
            let accessTokenObj = await decodeJwt(authorization)

            if (decodedToken.hash !== accessTokenObj.hash) {
                throw new AuthFailureError('Invalid credentials. Please login with your details');
            }

            const currentUser = await UserRepository.findOne({
                where: { id: decodedToken.sub },
                select: { id: true, isActive: true }
            });
            let key = currentUser
                ? await RefreshRepository.delete({
                    user: currentUser, refreshKey: decodedToken.key
                })
                : false;

            if (!currentUser || !key)
                throw new AuthFailureError('Invalid credentials. Please login with your details.');

            req.user = currentUser;
            req.decodedToken = decodedToken;
            return next();
        } catch (error: any) {
            if (error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
                let err = new AuthFailureError('Invalid credentials. Please login with your details');
                return next(err);
            }
            next(error);
        }
    }

    async refreshAccess(req: ProtectedRequest, res: Response, next: NextFunction) {
        try {

            const { id, email, role } = req.user;
            const hash = crypto.randomBytes(20).toString('hex');
            const code = crypto.randomBytes(18).toString('hex');

            const access_token = jwt.sign({ _id, email, role, hash, session_token: code }, cert, {
                expiresIn: token_expiry_timeframe,
                algorithm: 'RS256',
            });

            const Session = require('../models/token/token');
            await Promise.all([
                Session.create({
                    session_token: code,
                    parent: req.decodedToken.session_token,
                    createdAt: Date(),
                    user_id: req.user._id,
                }),
                await Session.findOneAndUpdate(
                    { user_id: req.user._id, session_token: req.decodedToken.session_token },
                    { child: code },
                ).lean(),
            ]);
            const refresh_token = jwt.sign({ _id, email, role, session_token: code, hash }, SECRET, {
                expiresIn: refresh_token_expiry_timeframe,
            });

            let token_expiry = is_app ? process.env.APP_TOKEN_EXPIRY_TIME ?? 1 : process.env.TOKEN_EXPIRY_TIME ?? 1;
            token_expiry = Number(token_expiry);
            let logins_tracker_expiration = Number(process.env.LOGINS_TRACKER_TIMEFRAME ?? 2);

            await Promise.all([
                rdSet(
                    `${role}-${_id}-${hash}`,
                    JSON.stringify({ _id, email, role, expiresIn: Date.now() + token_expiry * 3600 * 1000 }),
                ),
                rdSadd(`${role}-${_id}`, `${hash}`),
                rdExp(`${role}-${_id}-${hash}`, token_expiry * 3600),
                rdExp(`${role}-${_id}`, logins_tracker_expiration * 3600),
                rdDel(`${role}-${_id}-${accessTokenObj.hash}`),
                rdSrem(`${role}-${_id}`, `${accessTokenObj.hash}`),
                // Verification.updateMany({ session: accessTokenObj.hash }, { session: hash }).lean(),
            ]);
            const amqp = require('./queue');
            let data = { _id: req.user._id, session: hash, old_session: accessTokenObj.hash };

            let payload = { event: 'new_session', data };
            await amqp.PublishToQueue('payment_queue', payload, { persistent: true });

            req.msg = 'Token successfully refreshed';
            req.addToken = true;
            req.hash = hash;
            req.data = { access_token, refresh_token };
            return next();
        } catch (error) {
            return next(error);
        }
    }

    async hashPassword(password: string) {
        let salt = SALT_ROUNDS || 10
        const hashedPassword = await bcrypt.hash(password, salt);
        return hashedPassword;
    }

    async isPassword(password: string, dbPassword: string) {
        const isPassword = await bcrypt.compare(password, dbPassword);
        return isPassword;
    }

    public static logout(req: ProtectedRequest, res: Response, next: NextFunction) {
        res.cookie('vck', 'loggedOut', { httpOnly: true});
        return res.status(200).json({
            status: 'success',
            message: 'Successfully logged out',
            token: null,
        })
    }

    checkIfUserIsActive(req: ProtectedRequest, res: Response, next: NextFunction) {
        try {
            if (req.user?.isActive !== true) throw new ForbiddenError('Your account is currently suspended');
            return next();
        } catch (error) {
            return next(error);
        }
    }
};
