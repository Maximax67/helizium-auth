import {
  Entity,
  Column,
  ManyToOne,
  JoinColumn,
  BeforeInsert,
  BeforeUpdate,
  Index,
  PrimaryGeneratedColumn,
  CreateDateColumn,
} from 'typeorm';
import { User } from '../../users/entities';
import { Entities } from '../../../common/enums';
import { config } from '../../../config';

@Entity(Entities.API_TOKEN)
export class ApiToken {
  @PrimaryGeneratedColumn('uuid')
  jti: string;

  @Index()
  @Column({ type: 'bytea', nullable: false })
  userId: Buffer;

  @Column({ type: 'text', nullable: false })
  title: string;

  @Column({ nullable: false })
  writeAccess: boolean;

  @CreateDateColumn()
  createdAt: Date;

  @ManyToOne(() => User, (user) => user.apiTokens, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user: User;

  @BeforeInsert()
  @BeforeUpdate()
  async validateTokenLimit() {
    const apiTokenRepo = (this.constructor as any).getRepository(ApiToken);
    const tokenCount = await apiTokenRepo.count({
      where: { userId: this.userId },
    });

    if (tokenCount >= config.security.apiTokensLimitPerUser) {
      throw new Error('Max API tokens reached');
    }
  }
}
