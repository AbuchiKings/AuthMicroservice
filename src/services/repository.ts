import AppDataSource from "../data-source";
import { RefreshKeys } from "entity/RefreshKey";
import { Users } from "../entity/User"

export const UserRepository = AppDataSource.getRepository(Users);
export const RefreshRepository = AppDataSource.getRepository(RefreshKeys);


