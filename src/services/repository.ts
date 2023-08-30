import AppDataSource from "../data-source";
import { Users } from "../entity/User"

export const UserRepository = AppDataSource.getRepository(Users);


