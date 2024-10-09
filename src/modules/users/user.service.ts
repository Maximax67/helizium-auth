import { Inject, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { QueryRunner, Repository } from 'typeorm';

import { User } from './entities';
import { HashService } from './hash.service';
import { SignInDto, SignUpDto } from '../../common/dtos';
import { TokenLimits, MfaMethods } from '../../common/enums';

import { MfaInfo } from '../../common/interfaces';
import { VerifiedUser } from './interfaces';

import { ClientGrpc } from '@nestjs/microservices';
import { UsersServiceClient } from './users.grpc';
import { firstValueFrom } from 'rxjs';
import { SYSTEM_USERNAME } from '../../common/constants';

@Injectable()
export class UserService {
  private usersServiceClient: UsersServiceClient;

  constructor(
    private readonly hashService: HashService,

    @InjectRepository(User)
    private usersRepository: Repository<User>,

    @Inject('USERS_PACKAGE') private readonly client: ClientGrpc,
  ) {}

  onModuleInit() {
    this.usersServiceClient =
      this.client.getService<UsersServiceClient>('UsersService');
  }

  async createUser(userData: SignUpDto): Promise<string> {
    const { username, email, password } = userData;

    if (username.toLowerCase() === SYSTEM_USERNAME.toLowerCase()) {
      throw new Error('User with the same username or email already exists');
    }

    const userExists = await this.usersRepository.findOne({
      where: { username, email },
      select: ['isDeleted'],
    });

    if (userExists) {
      if (userExists.isDeleted) {
        throw new Error('User with the same username or email was deleted');
      }

      throw new Error('User with the same username or email already exists');
    }

    const userIdResponse = await firstValueFrom(
      this.usersServiceClient.signUp({ username, email }),
    );
    const userId = userIdResponse.userId;

    const passwordHash = await this.hashService.hashData(password);

    await this.usersRepository.insert({
      id: Buffer.from(userId, 'hex'),
      username,
      email,
      passwordHash,
    });

    return userId;
  }

  private async performUserUpdate(
    userId: string,
    updateData: any,
    remoteServiceCall: () => Promise<void>,
  ): Promise<boolean> {
    const queryRunner: QueryRunner =
      this.usersRepository.manager.connection.createQueryRunner();
    await queryRunner.startTransaction();

    try {
      const result = await queryRunner.manager.update(
        this.usersRepository.target,
        { id: Buffer.from(userId, 'hex'), isDeleted: false },
        updateData,
      );

      if (!result.affected) {
        await queryRunner.rollbackTransaction();
        return false;
      }

      try {
        await remoteServiceCall();
      } catch (error) {
        // Ignore the exception with code 9 (FAILED_PRECONDITION) or 5 (NOT_FOUND).
        if (
          !error ||
          ((error as any).code !== 9 && (error as any).code !== 5)
        ) {
          throw error;
        }
      }

      await queryRunner.commitTransaction();
      return true;
    } catch (error) {
      await queryRunner.rollbackTransaction();
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  async ban(userId: string): Promise<boolean> {
    return await this.performUserUpdate(
      userId,
      { isBanned: true, isDeleted: false },
      async () => {
        await firstValueFrom(this.usersServiceClient.unbanUser({ userId }));
      },
    );
  }

  async unban(userId: string): Promise<boolean> {
    return await this.performUserUpdate(
      userId,
      { isBanned: false, isDeleted: false },
      async () => {
        await firstValueFrom(this.usersServiceClient.unbanUser({ userId }));
      },
    );
  }

  async delete(userId: string): Promise<boolean> {
    return await this.performUserUpdate(
      userId,
      {
        isDeleted: true,
        passwordHash: null,
        totpSecret: null,
        isMfaRequired: false,
      },
      async () => {
        await firstValueFrom(this.usersServiceClient.deleteUser({ userId }));
      },
    );
  }

  async getUserEmailAndUsername(userId: string): Promise<User | null> {
    return await this.usersRepository.findOne({
      where: { id: Buffer.from(userId, 'hex') },
      select: ['email', 'username'],
    });
  }

  async verifyUser(signInData: SignInDto): Promise<VerifiedUser | null> {
    const { login, password } = signInData;

    const findParams = login.includes('@')
      ? { email: login.toLowerCase(), isDeleted: false }
      : { username: login, isDeleted: false };

    const user = await this.usersRepository.findOne({
      where: findParams,
      select: [
        'id',
        'passwordHash',
        'isEmailConfirmed',
        'isBanned',
        'isMfaRequired',
        'totpSecret',
      ],
    });

    if (
      user &&
      user.passwordHash &&
      (await this.hashService.compareHash(password, user.passwordHash))
    ) {
      let limits = TokenLimits.DEFAULT;
      if (user.isMfaRequired) {
        limits = TokenLimits.MFA_REQUIRED;
      } else if (user.isBanned) {
        limits = TokenLimits.USER_BANNED;
      } else if (!user.isEmailConfirmed) {
        limits = TokenLimits.EMAIL_NOT_CONFIRMED;
      }

      const mfa = this.getMfaInfo(user.isMfaRequired, !!user.totpSecret);

      return { userId: user.id.toString('hex'), limits, mfa };
    }

    return null;
  }

  async isUserHasLimits(userId: string): Promise<TokenLimits | null> {
    const user = await this.usersRepository.findOne({
      where: { id: Buffer.from(userId, 'hex'), isDeleted: false },
      select: ['isBanned', 'isEmailConfirmed'],
    });

    if (!user) {
      return null;
    }

    if (user.isBanned) {
      return TokenLimits.USER_BANNED;
    }

    if (!user.isEmailConfirmed) {
      return TokenLimits.EMAIL_NOT_CONFIRMED;
    }

    return TokenLimits.DEFAULT;
  }

  async getUserLimitsIfBecameRoot(userId: string): Promise<TokenLimits | null> {
    const noRootLimits = await this.isUserHasLimits(userId);
    if (!noRootLimits) {
      return null;
    }

    if (noRootLimits === TokenLimits.USER_BANNED) {
      return TokenLimits.BANNED_ROOT;
    }

    return TokenLimits.ROOT;
  }

  async confirmEmailIfNotConfirmed(userId: string): Promise<boolean> {
    const result = await this.usersRepository.update(
      { id: Buffer.from(userId, 'hex'), isEmailConfirmed: false },
      { isEmailConfirmed: true },
    );

    return !!result.affected;
  }

  private getMfaInfo(mfaRequired: boolean, isTotpSet: boolean): MfaInfo {
    const methods = isTotpSet
      ? [MfaMethods.EMAIL, MfaMethods.TOTP]
      : [MfaMethods.EMAIL];

    return {
      required: mfaRequired,
      methods,
    };
  }

  async getUserMfaInfo(userId: string): Promise<MfaInfo> {
    const user = await this.usersRepository.findOne({
      where: { id: Buffer.from(userId, 'hex'), isDeleted: false },
      select: ['isMfaRequired', 'totpSecret'],
    });

    if (!user) {
      throw new Error('User not found');
    }

    return this.getMfaInfo(user.isMfaRequired, !!user.totpSecret);
  }

  async changeMfaRequired(userId: string, required: boolean): Promise<void> {
    const result = await this.usersRepository.update(
      {
        id: Buffer.from(userId, 'hex'),
        isMfaRequired: required,
        isDeleted: false,
      },
      { isMfaRequired: required },
    );

    if (!result.affected) {
      throw new Error('Not modified');
    }
  }

  async disableTotpMfa(userId: string): Promise<void> {
    await this.usersRepository.update(
      { id: Buffer.from(userId, 'hex'), isDeleted: false },
      { totpSecret: null },
    );
  }

  async setTotpSecret(userId: string, totpSecret: string): Promise<void> {
    await this.usersRepository.update(
      { id: Buffer.from(userId, 'hex'), isDeleted: false },
      { totpSecret },
    );
  }

  async getTotpSecret(userId: string): Promise<string | null> {
    const searchResult = await this.usersRepository.findOne({
      where: { id: Buffer.from(userId, 'hex'), isDeleted: false },
      select: ['totpSecret'],
    });

    if (!searchResult) {
      throw new Error('User not found');
    }

    return searchResult.totpSecret ?? null;
  }
}
