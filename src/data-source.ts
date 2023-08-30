import "reflect-metadata"
import dotenv from 'dotenv';
import { DataSource } from "typeorm"

import { CONTAINER, NODE_ENV } from './config'
import { Users } from "./entity/User"

dotenv.config();

let { DB_HOST, DB_PORT, DB_USER, DB_PASS, DB_NAME } = process.env;
let port = Number(DB_PORT)

const AppDataSource = new DataSource({
    type: "postgres",
    host: CONTAINER ? DB_HOST : 'localhost',
    port: port,
    username: DB_USER,
    password: DB_PASS,
    database: DB_NAME,
    synchronize: NODE_ENV === 'production' ? false : true,
    logging: NODE_ENV === 'production' ? false : ["query", "error"],
    entities: [Users],
    migrations: [],
    subscribers: [],
})

AppDataSource.initialize().then((data) => {
    //Logger
    console.log(`Connected to ${data.options.database} database successfully`);
}).catch((error) => {
    console.log(error);
    // Logger
    //roll bar
})

export default AppDataSource;