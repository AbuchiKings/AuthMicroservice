import { Entity, PrimaryGeneratedColumn, Column } from "typeorm"

@Entity()
export class Users {

    @PrimaryGeneratedColumn()
    id: number

    @Column()
    firstName: string

    @Column()
    lastName: string

    @Column()
    isActive: boolean

    @Column()
    role: string

    @Column()
    age: number

}
