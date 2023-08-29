import 'reflect-metadata'
import 'data-source'
import compression from 'compression';
import cookieParser from 'cookie-parser'
import cors from 'cors';
import express, { Application, Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import preventParameterPollution from 'hpp'
import requestIp from 'request-ip'

import { WHITELIST } from './config'

const app: Application = express();

const whitelist = WHITELIST ? WHITELIST.split(',') : [];

let options = {
    origin: whitelist,
    credentials: true,
};
app.use('*', cors(options));

app.set('trust proxy', true);
app.use((req: Request, res: Response, next: NextFunction) => {
    const client_ip = requestIp.getClientIp(req);
    client_ip ? req.headers['x-real-ip'] = client_ip : {};
    next()
});

app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());
app.use(helmet());

app.use(preventParameterPollution());
app.use(compression());

// app.use(v1);
// app.use(globalErrorHandler);

export default app;