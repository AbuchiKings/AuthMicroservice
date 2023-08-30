import crypto from 'crypto';
import { promisify } from 'util';

import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction, Router } from 'express';

import { InternalError, AuthFailureError, ForbiddenError } from '../utils/requestUtils/ApiError';
import { ProtectedRequest, RequestFunction, UserInterface } from '../interfaces/interfaces'
import { SuccessResponse } from '../utils/requestUtils/ApiResponse';
import { UserRepository } from '../services/repository';

import { getAccessToken, signToken, validateToken, JwtPayload } from './authUtils';
import { rdGet, rdSet, rdSadd, rdSrem, rdExp, rdDel, rdSmem, rdHget, rdHset } from '../utils/cache';
//import { readPublicKey, readPrivateKey } from './authUtils';
//import { taskQueue } from '../jobs/jobs';
import { SECRET, ITERATIONS, HASH_BYTES, SALT_BYTES, SALT_ROUNDS } from '../config';

//Router().post('/', Auth.verifyToken)

class Auth {
    public static async verifyToken(req: ProtectedRequest, res: Response, next: NextFunction) {
        try {
            const token = getAccessToken(req.headers.authorization);
            if (!token) throw new AuthFailureError('Unauthorised. Please login with your details');

            const decodedToken = await validateToken(token);

            const User = require('../models/user/user');
            const fields = ['+verification_count', '+reset_count', '+verification_expires', '+reset_expires'];

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

            const currentUser = await UserRepository.findOne({ where: { id: decodedToken.sub, isActive: true, role: 'user' } })
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

    public static async signToken(req: ProtectedRequest, res: Response, next: NextFunction){
        try {

        let { id, email, role } = req.user;
        const hash = crypto.randomBytes(20).toString('hex');
        const sessionToken = crypto.randomBytes(20).toString('hex');

        const is_app = req.headers['x-app'];
        let token_expiry_timeframe = is_app
            ? process.env.APP_TOKEN_EXPIRATION_TIMEFRAME ?? '1h'
            : process.env.TOKEN_EXPIRATION_TIMEFRAME ?? '1h';

        let refresh_token_expiry_timeframe = is_app
            ? process.env.APP_REFRESH_EXPIRATION_TIMEFRAME ?? '3h'
            : process.env.REFRESH_EXPIRATION_TIMEFRAME ?? '3h';

        const access_token = jwt.sign({ id, email, role, hash}, cert, {
            expiresIn: token_expiry_timeframe,
            algorithm: 'RS256',
        });

        const refresh_token = jwt.sign({ id, role, hash, sessionToken: sessionToken  }, SECRET, {
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
        ]);

        req.access_token = access_token;
        req.refresh_token = refresh_token;
        req.hash = hash;
        return next();
    } catch (error) {
        next(error);
    }
}

addToken(req, res, next) {
    const access_token = req.access_token;
    const refresh_token = req.refresh_token;
    const cookieOptions = {
        httpOnly: true,
        expires: new Date(Date.now() + (process.env.APP_TOKEN_EXPIRY_TIME ?? 1) * 1000 * 60 * 60 * 24),
        sameSite: 'None',
        secure: process.env.NODE_ENV !== 'development' ? true : false,
        domain: process.env.NODE_ENV !== 'development' ? process.env.ORIGIN || 'fuspay.finance' : undefined,
        hostOnly: process.env.NODE_ENV !== 'development' ? false : undefined,
    };
    const message = req.message || 'Successfully logged in';
    process.env.NODE_ENV === 'development' ? res.cookie('jwt', access_token, cookieOptions) : {};

    let data = {
        access_token,
        refresh_token,
        ...req.user,
        verification_required: req.verification_required,
    };
    if (req.addToken) {
        req.data = data;
        return next();
    }

    return new SuccessResponse(message, 1, data).send(res);
},

    async addVerificationCookie(req, res, next) {
    try {
        if (!req.addToken) {
            const message = req.message || 'Successfully logged in.';
            return new SuccessResponse(message, 0).send(res);
        }
        let hash = req.hash || req.decodedToken?.hash;
        const { _id, is_verified } = req.user;
        const key_source = req.user.settings.google_two_fa ? 'auth_2fa' : 'verify';
        const cert = await readPrivateKey(key_source);
        if (!cert) throw new InternalError('Token generation failure');

        const is_app = req.headers['x-app'];

        let verification_expiry_timeframe = is_app
            ? process.env.APP_VERIFICATION_TIMEFRAME ?? '1d'
            : process.env.VERIFICATION_TIMEFRAME ?? '1d';

        let verification_expiry = is_app ? process.env.APP_VERIFICATION_EXPIRY ?? 1 : process.env.VERIFICATION_EXPIRY ?? 1;

        const vck = jwt.sign({ _id, is_verified, hash }, cert, {
            expiresIn: verification_expiry_timeframe,
            algorithm: 'RS256',
        });
        const cookieOptions = {
            httpOnly: true,
            expires: new Date(Date.now() + verification_expiry * 1000 * 60 * 60 * 24),
            sameSite: 'None',
            secure: process.env.NODE_ENV !== 'development' ? true : false,
            domain: process.env.NODE_ENV !== 'development' ? process.env.ORIGIN || 'fuspay.finance' : undefined,
            hostOnly: process.env.NODE_ENV !== 'development' ? false : undefined,
        };
        res.cookie('vck', vck, cookieOptions);
        let message = 'Successfully verified.';
        req.msg ? (message = req.msg) : {};
        const data = req.data || null;

        return new SuccessResponse(message, 1, data).send(res);
    } catch (error) {
        return next(error);
    }
},

    async checkIfUserIs2faVerified(req, res, next) {
    try {
        // let reg = /\/transaction\/(pending|complete-transaction)/;
        // if (req.originalUrl.match(reg) && req.originalUrl.match(reg)[0]) return next();
        if (!req.user.settings.two_fa) return next();
        let token;
        if (req.cookies && req.cookies.vck) {
            token = req.cookies.vck;
        }
        if (!token) throw new ForbiddenError('Verification Required.'); // edit message with care

        const key_source = req.user.settings.google_two_fa ? 'auth_2fa' : 'verify';
        const cert = await readPublicKey(key_source);
        if (!cert) throw new InternalError('Authentication error.');

        const decodedToken = await promisify(jwt.verify)(token, cert);
        if (
            !decodedToken.is_verified ||
            `${decodedToken._id}` !== `${req.user._id}` ||
            `${decodedToken.hash}` !== `${req.decodedToken.hash}`
        ) {
            throw new ForbiddenError('Verification Required.');
        }
        return next();
    } catch (error) {
        if (['TokenExpiredError', 'JsonWebTokenError'].includes(error.name)) {
            let err = new ForbiddenError('Verification Required.');
            return next(err);
        }
        return next(error);
    }
},

    async checkIfVerificationIsRequired(req, res, next) {
    if (!req.user.settings.two_fa) return next();

    let token;
    if (req.cookies && req.cookies.vck) {
        token = req.cookies.vck;
    }
    if (!token) {
        req.verification_required = true;
        req.user.settings.google_two_fa ? {} : await auth.genVerificationCode(req.user);
        return next();
    }

    let decodedToken;
    const key_source = req.user.settings.google_two_fa ? 'auth_2fa' : 'verify';
    const cert = await readPublicKey(key_source);
    if (!cert) throw new InternalError('Server error.');
    try {
        decodedToken = await promisify(jwt.verify)(token, cert);
    } catch (error) {
        req.user.settings.google_two_fa ? {} : await auth.genVerificationCode(req.user);
        req.verification_required = true;
        return next();
    }
    if (!decodedToken) return next();

    if (!decodedToken.is_verified || `${decodedToken._id}` !== `${req.user._id}`) {
        req.user.settings.google_two_fa ? {} : await auth.genVerificationCode(req.user);
        req.verification_required = true;
        return next();
    }
    req.addToken = true;
    return next();
},

    async checkIfRecoveryIsRequired(req, res, next) {
    try {
        if (!req.user.settings.two_fa || !req.user.settings.google_two_fa) {
            throw new ForbiddenError('Request declined.');
        }
        let token;
        if (req.cookies && req.cookies.vck) {
            token = req.cookies.vck;
        }
        if (!token) return next();
        const key_source = req.user.settings.google_two_fa ? 'auth_2fa' : 'verify';

        const cert = await readPublicKey(key_source);
        if (!cert) throw new InternalError('Server error.');

        const decodedToken = await promisify(jwt.verify)(token, cert);
        if (
            !decodedToken.is_verified ||
            `${decodedToken._id}` !== `${req.user._id}` ||
            `${decodedToken.hash}` !== `${req.decodedToken.hash}`
        ) {
            return next();
        }
        throw new ForbiddenError('Request declined.');
    } catch (error) {
        if (['TokenExpiredError', 'JsonWebTokenError'].includes(error.name)) {
            return next();
        }
        return next(error);
    }
},

    async checkIfUserIsVerified(req, res, next) {
    try {
        if (!req.user.is_verified) {
            throw new ForbiddenError('Please verify your account to proceed');
        }
        return next();
    } catch (error) {
        return next(error);
    }
},

genVerificationCode: async (user) => {
    const { code } = user.createCode({ verificationToken: true });
    await user.save();

    process.env.NO_PROD === 'true' ? console.log(code) // eslint-disable-line
        : taskQueue
            .add(
                `send_mail`,
                {
                    to: user.email,
                    type: 'html',
                    subject: 'Verification Code',
                    data: { code, text1: 'Complete Your Verification', fullname: user.fullname },
                    template: 'verification',
                },
                { removeOnComplete: true },
            )
            .catch((error) => {
                logError(error);
                return;
            });
    return;
},

    validateRefreshToken: async (req, res, next) => {
        try {
            let token = req.headers['x-refresh-token'];

            if (!token) throw new AuthFailureError('Invalid credentials. Please login with your details.');

            const decodedToken = await promisify(jwt.verify)(token, SECRET);

            const User = require('../models/user/user');
            const Session = require('../models/token/token');

            const fields = ['email', 'role', 'is_verified', 'is_active', 'settings'];
            const currentUser = await User.findOne({ _id: decodedToken._id }).select(fields).lean();

            let session_token = currentUser
                ? await Session.findOne({
                    user_id: currentUser._id,
                    session_token: decodedToken.session_token,
                }).lean()
                : false;

            if (!currentUser || !session_token)
                throw new AuthFailureError('Invalid credentials. Please login with your details.');

            /**
             * If refresh token has child, then refresh token is being reused
             * delete all refresh tokens
             * delete all access tokens
             */
            if (session_token.child) {
                const amqp = require('../helper/queue');

                await Promise.all([
                    Session.deleteMany({ user_id: currentUser._id }).lean(),
                    User.findOneAndUpdate({ _id: currentUser._id }, { is_verified: false }).select('email').lean(),
                ]);

                const sessions = await rdSmem(`${currentUser.role}-${currentUser._id}`);
                const deletAllSessions = sessions.map((sess) => {
                    return rdDel(`${currentUser.role}-${currentUser._id}-${sess}`);
                });
                await Promise.all([...deletAllSessions, rdDel(`${currentUser.role}-${currentUser._id}`)]);
                res.clearCookie('vck');

                let payload = { event: 'user_updated', data: { ...currentUser, is_verified: false } };
                await amqp.PublishMessage('user', payload, '', 'fanout', { persistent: true });

                throw new AuthFailureError('Suspiscious activity detected. Please login and verify your account to proceed.');
            }
            req.user = currentUser;
            req.decodedToken = decodedToken;
            req.session_token = session_token;
            return next();
        } catch (error) {
            if (error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
                let err = new AuthFailureError('Invalid credentials. Please login with your details');
                return next(err);
            }
            next(error);
        }
    },

        async refreshAccess(req, res, next) {
    try {
        const cert = await readPrivateKey('user');
        if (!cert) throw new InternalError('Token generation failure');
        const accessTokenObj = await auth.decodeJwt(req, 'authorization');

        const { _id, email, role } = req.user;
        const hash = crypto.randomBytes(20).toString('hex');
        const code = crypto.randomBytes(18).toString('hex');

        const is_app = req.headers['x-app'];
        let token_expiry_timeframe = is_app
            ? process.env.APP_TOKEN_EXPIRATION_TIMEFRAME ?? '1h'
            : process.env.TOKEN_EXPIRATION_TIMEFRAME ?? '1h';

        let refresh_token_expiry_timeframe = is_app
            ? process.env.APP_REFRESH_EXPIRATION_TIMEFRAME ?? '3h'
            : process.env.REFRESH_EXPIRATION_TIMEFRAME ?? '3h';

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
},

    async decodeJwt(req, name) {
    const access = req.headers[name];
    let token;
    if (access && access.startsWith('Bearer')) {
        let bearerToken = access.split(' ');
        token = bearerToken[1];
    } else {
        throw new AuthFailureError(`${name} missing in headers.`);
    }

    if (!token) throw new AuthFailureError(`${name} missing in headers.`);

    const cert = await readPublicKey('user');
    if (!cert) throw new InternalError('Authentication error.');

    const accessTokenObj = await promisify(jwt.verify)(token, cert, { ignoreExpiration: true });
    if (req.decodedToken.hash !== accessTokenObj.hash) {
        throw new AuthFailureError('Invalid credentials. Please login with your details');
    }
    return accessTokenObj;
},

    // async verifyJwt(req, res, next) {
    //     const accessTokenObj = await auth.decodeJwt(req, 'authorization');
    //     const User = require('../models/user/user');

    //     const { _id } = accessTokenObj;

    //     const currentUser = await User.findOne({ _id: _id }).lean()
    //     if (!currentUser) return errorHandler(401, `Unauthorised. Please login with your details.`);

    //     req.user = currentUser;
    //     req.decodedToken = accessTokenObj;
    //     return next();
    // },

    async hashPassword(password) {
    const hashedPassword = await bcrypt.hash(password, salt_rounds);
    return hashedPassword;
},

    async isPassword(password, dbPassword) {
    const isPassword = await bcrypt.compare(password, dbPassword);
    return isPassword;
},

hashPIN(pin, cb = () => { }) {
    return new Promise((resolve, reject) => {
        const salt = crypto.randomBytes(saltBytes).toString('hex');
        const callback = (error, buffer) => {
            if (error) {
                cb(error);
                return reject(error);
            }
            const hash = buffer.toString('hex');
            const hashpassword = [salt, hash].join('$');
            resolve(hashpassword);
            cb(null, hashpassword);
        };
        return crypto.pbkdf2(pin, salt, iterations, hashBytes, 'sha512', callback);
    });
},

isPIN(pin, dbPin, cb = () => { }) {
    return new Promise((resolve, reject) => {
        const originalHash = dbPin.split('$')[1];
        const salt = dbPin.split('$')[0];
        crypto.pbkdf2(pin, salt, iterations, hashBytes, 'sha512', (error, pwdBuffer) => {
            if (error) {
                cb(error);
                return reject(error);
            }
            resolve(pwdBuffer.toString('hex') === originalHash);
            cb(null, pwdBuffer.toString('hex'));
        });
    });
},
// eslint-disable-next-line
logout: (req, res, next) => {
    res.clearCookie('jwt');
    const cookieOptions = {
        httpOnly: true,
        sameSite: 'None',
        secure: process.env.NODE_ENV === 'production' ? true : false,
        expires: new Date(Date.now() - 5 * 1000),
    };
    res.cookie('vck', 'loggedOut', cookieOptions);
    return res.status(200).json({
        status: 'success',
        message: 'Successfully logged out',
        token: null,
    });
},

    verifyContingencyCookie: async (req, res, next) => {
        try {
            let cookie;
            if (req.cookies && req.cookies.contingency) {
                cookie = req.cookies.contingency;
            }
            if (!cookie) throw new ForbiddenError('Invalid Request.');
            let session = await rdGet(`contingency:${req.body.user_email}`);
            if (!session) throw new ForbiddenError('Invalid Request');
            session = crypto.createHmac('sha512', process.env.HASH_KEY).update(session).digest('hex');
            if (cookie !== session) throw new ForbiddenError('Invalid Request');
            return next();
        } catch (error) {
            return next(error);
        }
    },

        checkIfUserIsActive(req, res, next) {
    try {
        if (req.user && req.user.is_active !== true) throw new ForbiddenError('Your account is currently suspended');
        return next();
    } catch (error) {
        return next(error);
    }
},
};

module.exports = auth;
