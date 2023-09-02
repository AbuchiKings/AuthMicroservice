import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, ManyToOne, Index } from "typeorm"

import { Users } from "./User"


@Entity()
export class RefreshKeys {
    @PrimaryGeneratedColumn('increment')
    id: number

    @Column()
    refreshKey: string

    @CreateDateColumn({ type: "timestamp", default: () => "CURRENT_TIMESTAMP(6)" })
    createdAt: Date

    @ManyToOne(() => Users, { cascade: ["remove"] })
    @Index()
    user: Users
}
