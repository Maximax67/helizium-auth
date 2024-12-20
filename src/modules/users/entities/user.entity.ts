import {
  Entity,
  Column,
  OneToMany,
  Index,
  PrimaryColumn,
  UpdateDateColumn,
  CreateDateColumn,
} from 'typeorm';
import { Entities } from '../../../common/enums';
import { ApiToken } from '../../../modules/tokens/entities';

@Entity(Entities.USER)
export class User {
  @PrimaryColumn({ type: 'bytea' })
  id: Buffer;

  @Index()
  @Column({ unique: true, nullable: false })
  username: string;

  @Index()
  @Column({ unique: true, nullable: false })
  email: string;

  @Column({ type: 'text', nullable: true })
  passwordHash!: string | null;

  @Column({ default: false })
  isBanned: boolean;

  @Column({ default: false })
  isDeleted: boolean;

  @Column({ default: false })
  isMfaRequired: boolean;

  @Column({ default: false })
  isEmailConfirmed: boolean;

  @Column({ type: 'text', nullable: true })
  totpSecret!: string | null;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @OneToMany(() => ApiToken, (apiToken) => apiToken.user)
  apiTokens: ApiToken[];
}
