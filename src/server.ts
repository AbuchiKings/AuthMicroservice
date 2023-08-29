
require('dotenv').config();

import http from 'http';
import app from './app';

import { PORT } from './config'
const server = http.createServer(app);

server.listen(PORT || 8001, () => {
    console.log(`\n✔ Server is listening on port ${PORT || 8001} on: `); // eslint-disable-line
    console.log(`  localhost: http://localhost:$${PORT || 8001}`); // eslint-disable-line
});

process.on('unhandledRejection', (error) => {
    // eslint-disable-next-line
    console.log(error)
    server.close(() => {
        process.exit(1);
    });
});

process.on('SIGTERM', () => {
    server.close(() => {
        // eslint-disable-next-line
        console.log('Process terminated!')
    });
});

process.on('uncaughtException', (error) => {
    // eslint-disable-next-line
    console.log(error)
    server.close(() => {
        process.exit(1);
    });
});