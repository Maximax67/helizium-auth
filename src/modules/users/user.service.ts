import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, ProjectionType, Types } from 'mongoose';

import { User } from './schemas';
import { HashService } from './hash.service';
import { SignInDto, SignUpDto } from '../../common/dtos';
import { TokenLimits, MfaMethods } from '../../common/enums';

import { MfaInfo } from '../../common/interfaces';
import { VerifiedUser } from './interfaces';

@Injectable()
export class UserService {
  constructor(
    private readonly hashService: HashService,

    @InjectModel(User.name)
    private readonly userModel: Model<User>,
  ) {}

  async createUser(userData: SignUpDto): Promise<Types.ObjectId> {
    const { username, email, password } = userData;
    const passwordHash = await this.hashService.hashData(password);

    try {
      const newUser = await this.userModel.create({
        username,
        email,
        passwordHash,
      });

      return newUser._id;
    } catch (error) {
      if (
        error instanceof Error &&
        'code' in error &&
        (error as any).code === 11000
      ) {
        //throw ApiError.fromTemplate(ApiErrorTemplates.UserAlreadyExists);
      }

      throw error;
    }
  }

  async getUserById(
    userId: string,
    projection?: ProjectionType<User>,
  ): Promise<User | null> {
    return await this.userModel.findById(userId, projection).lean();
  }

  async verifyUser(signInData: SignInDto): Promise<VerifiedUser | null> {
    const { login, password } = signInData;

    const findParams = login.includes('@')
      ? { email: login }
      : { username: login };

    const user = await this.userModel
      .findOne(findParams, {
        passwordHash: 1,
        isEmailConfirmed: 1,
        isBanned: 1,
        mfaRequired: 1,
        totpSecret: 1,
      })
      .lean();

    if (
      user &&
      (await this.hashService.compareHash(password, user.passwordHash))
    ) {
      let limits = TokenLimits.DEFAULT;
      if (user.mfaRequired) {
        limits = TokenLimits.MFA_REQUIRED;
      } else if (user.isBanned) {
        limits = TokenLimits.USER_BANNED;
      } else if (!user.isEmailConfirmed) {
        limits = TokenLimits.EMAIL_NOT_CONFIRMED;
      }

      const mfa = this.getMfaInfo(user.mfaRequired, !!user.totpSecret);

      return { userId: user._id, limits, mfa };
    }

    return null;
  }

  async isUserHasLimits(userId: string): Promise<TokenLimits | null> {
    const user = await this.userModel
      .findById(userId, {
        isEmailConfirmed: 1,
        isBanned: 1,
      })
      .lean();

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
    const result = await this.userModel.findOneAndUpdate(
      {
        _id: userId,
        isEmailConfirmed: false,
      },
      {
        $set: {
          isEmailConfirmed: true,
        },
      },
    );

    return result !== null;
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
    const user = await this.userModel
      .findById(userId, {
        mfaRequired: 1,
        totpSecret: 1,
      })
      .lean();

    if (!user) {
      throw new Error('User not found');
    }

    return this.getMfaInfo(user.mfaRequired, !!user.totpSecret);
  }

  async changeMfaRequired(userId: string, required: boolean): Promise<void> {
    await this.userModel.findByIdAndUpdate(userId, {
      $set: {
        mfaRequired: required,
      },
    });
  }

  async disableTotpMfa(userId: string): Promise<void> {
    await this.userModel.findByIdAndUpdate(userId, {
      $set: {
        totpSecret: null,
      },
    });
  }

  async setTotpSecret(userId: string, totpSecret: string): Promise<void> {
    await this.userModel.findByIdAndUpdate(userId, {
      $set: {
        totpSecret,
      },
    });
  }

  async getTotpSecret(userId: string): Promise<string | null> {
    const searchResult = await this.userModel.findById(userId, {
      totpSecret: 1,
    });
    if (!searchResult) {
      throw new Error('User not found');
    }

    return searchResult.totpSecret ?? null;
  }
}
