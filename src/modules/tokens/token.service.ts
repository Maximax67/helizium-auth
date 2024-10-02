import * as jwt from 'jsonwebtoken';
import axios from 'axios';
import { nanoid } from 'nanoid';
import { Model } from 'mongoose';

import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';

import { ApiToken, ApiTokenDocument } from './schemas';
import { RedisService } from '../redis';
import { getKidMapping } from '../../common/helpers';
import { TokenTypes, TokenLimits, TokenStatuses } from '../../common/enums';

import { Token, TokenInfo } from '../../common/interfaces';
import {
  TokenPair,
  TokenPayload,
  TokenInfoWithStatus,
  GenerateTokenPayload,
} from './interfaces';
import { config } from '../../config';
import { ApiTokenDto } from './dtos';

@Injectable()
export class TokenService {
  constructor(
    private readonly redisService: RedisService,

    @InjectModel(ApiToken.name)
    private readonly apiTokenModel: Model<ApiToken>,
  ) {}

  private getUserTokensKeyPattern(userId: string): string {
    return `token:*:${userId}`;
  }

  private getTokenStorageKey(userId: string, jti: string): string {
    return `token:${jti}:${userId}`;
  }

  private async postRevocationRequest(jti: string): Promise<void> {
    await axios.post(
      config.apiGatewayTokenRevokeUrl,
      { jti },
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      },
    );
  }

  private async revokeForApiGateway(jti: string | string[]): Promise<void> {
    if (Array.isArray(jti)) {
      if (!jti.length) {
        return;
      }

      const jtiString = jti.join(',');
      await this.postRevocationRequest(jtiString);

      return;
    }

    await this.postRevocationRequest(jti);
  }

  async generateTokenPair(payload: GenerateTokenPayload): Promise<TokenPair> {
    const jti = nanoid();
    const tokenPayload: TokenPayload = {
      limits: TokenLimits.DEFAULT,
      ...payload,
      jti,
    };

    const accessToken = await this.generateAccessToken(tokenPayload);
    const refreshToken = await this.generateRefreshToken(tokenPayload);

    return {
      accessToken,
      refreshToken,
    };
  }

  private async generateRefreshToken(payload: TokenPayload): Promise<Token> {
    const { userId, jti, limits } = payload;
    const kid = (await getKidMapping()).REFRESH;
    const expiresIn = config.security.jwtRefreshTtl;
    const type = TokenTypes.REFRESH;
    const token = jwt.sign(
      { ...payload, type },
      config.keys.jwtRefreshPrivateKey,
      {
        expiresIn,
        algorithm: 'RS256',
        keyid: kid,
      },
    );

    const iat = Math.floor(Date.now() / 1000);
    const exp = iat + expiresIn;

    await this.setTokenStatus(userId, jti, TokenStatuses.ACTIVE, exp);

    return {
      token,
      type,
      kid,
      limits,
      jti,
      userId,
      iat,
      exp,
    };
  }

  private async generateAccessToken(payload: TokenPayload): Promise<Token> {
    const { userId, jti, limits } = payload;
    const kid = (await getKidMapping()).ACCESS;
    const expiresIn = config.security.jwtAccessTtl;

    const type = TokenTypes.ACCESS;
    const token = jwt.sign(
      { ...payload, type },
      config.keys.jwtAccessPrivateKey,
      {
        expiresIn,
        algorithm: 'RS256',
        keyid: kid,
      },
    );

    const iat = Math.floor(Date.now() / 1000);
    const exp = iat + expiresIn;

    return {
      token,
      kid,
      type,
      limits,
      jti,
      userId,
      iat,
      exp,
    };
  }

  async generateApiToken(
    userId: string,
    title: string,
    writeAccess: boolean,
  ): Promise<string> {
    const jti = nanoid();
    const type = TokenTypes.API;
    const kid = (await getKidMapping()).API;
    const limits = writeAccess ? TokenLimits.DEFAULT : TokenLimits.READ_ONLY;
    const payload = { userId, jti, limits, type };

    const token = jwt.sign(payload, config.keys.jwtApiPrivateKey, {
      algorithm: 'RS256',
      keyid: kid,
    });

    await this.apiTokenModel.create({
      userId,
      jti,
      title,
      writeAccess,
    });

    return token;
  }

  async validateToken(
    token: string,
    isApiToken: boolean,
  ): Promise<TokenInfoWithStatus | null> {
    try {
      const decoded = jwt.verify(
        token,
        isApiToken
          ? config.keys.jwtApiPublicKey
          : config.keys.jwtAccessPublicKey,
      );

      if (
        typeof decoded !== 'string' &&
        ((isApiToken && decoded.type === TokenTypes.API) ||
          (!isApiToken && decoded.type === TokenTypes.ACCESS && decoded.exp)) &&
        decoded.iat &&
        decoded.jti &&
        decoded.userId &&
        decoded.limits
      ) {
        const type = decoded.type;
        const jti = decoded.jti;
        const userId = decoded.userId;
        let status: TokenStatuses | null = TokenStatuses.ACTIVE;

        if (type === TokenTypes.ACCESS) {
          status = await this.getTokenRedisStatus(userId, jti);
          if (!status) {
            return null;
          }
        } else {
          const limits = decoded.limits;
          const searchResult = await this.apiTokenModel.findOne(
            { userId, jti },
            { writeAccess: 1 },
          );

          if (
            !searchResult ||
            (searchResult.writeAccess && limits !== TokenLimits.DEFAULT) ||
            (!searchResult.writeAccess && limits !== TokenLimits.READ_ONLY)
          ) {
            return null;
          }
        }

        return {
          decoded: decoded as TokenInfo,
          status,
        };
      }
    } catch (e) {}

    return null;
  }

  async validateRefreshToken(
    token: string,
  ): Promise<TokenInfoWithStatus | null> {
    try {
      const decoded = jwt.verify(token, config.keys.jwtRefreshPublicKey);

      if (
        typeof decoded !== 'string' &&
        decoded.type === TokenTypes.REFRESH &&
        decoded.iat &&
        decoded.exp &&
        decoded.jti &&
        decoded.userId &&
        decoded.limits
      ) {
        const tokenStatus = await this.getTokenRedisStatus(
          decoded.userId,
          decoded.jti,
        );

        if (tokenStatus) {
          return {
            decoded: decoded as TokenInfo,
            status: tokenStatus,
          };
        }
      }
    } catch (e) {}

    return null;
  }

  async getUserApiTokens(userId: string): Promise<ApiTokenDto[]> {
    const tokens: ApiTokenDto[] = await this.apiTokenModel
      .find({ userId })
      .lean();

    return tokens.map((token) => {
      token.id = (token as ApiTokenDocument)._id.toString();
      return token;
    });
  }

  async getUserApiToken(
    userId: string,
    tokenId: string,
  ): Promise<ApiTokenDto | null> {
    const token: ApiTokenDto | null = await this.apiTokenModel
      .findOne({ _id: tokenId, userId })
      .lean();

    if (!token) {
      throw new Error('Not found api token');
    }

    token.id = (token as ApiTokenDocument)._id.toString();

    return token;
  }

  async setTokenStatus(
    userId: string,
    jti: string,
    status: TokenStatuses,
    expires: number = config.security.jwtRefreshTtl,
  ): Promise<void> {
    const tokenStorageKey = this.getTokenStorageKey(userId, jti);
    await this.redisService.set(tokenStorageKey, status, expires);
  }

  async setAllUserTokensStatus(
    userId: string,
    status: TokenStatuses,
    expires: number = config.security.jwtRefreshTtl,
  ): Promise<void> {
    const tokenPattern = this.getUserTokensKeyPattern(userId);
    const tokens = await this.redisService.scanByPattern(tokenPattern);
    const mappedValues = tokens.map((token) => ({
      key: token,
      value: status,
      expiry: expires,
    }));

    await this.redisService.setMany(mappedValues);
  }

  async revokeTokenPair(decoded: TokenPayload): Promise<void> {
    const { userId, jti } = decoded;
    const tokenStorageKey = this.getTokenStorageKey(userId, jti);
    await this.redisService.delete(tokenStorageKey);
    await this.revokeForApiGateway(jti);
  }

  async revokeAllUserTokens(userId: string): Promise<void> {
    const tokensPattern = this.getUserTokensKeyPattern(userId);
    const tokenKeys = await this.redisService.scanByPattern(tokensPattern);
    await this.redisService.deleteMany(tokenKeys);

    const jtiValues = tokenKeys.map((key) => {
      const firstColonIndex = key.indexOf(':');
      const secondColonIndex = key.indexOf(':', firstColonIndex + 1);
      return key.substring(firstColonIndex + 1, secondColonIndex);
    });

    await this.revokeForApiGateway(jtiValues);
  }

  async revokeUserTokenByJti(userId: string, jti: string): Promise<void> {
    const tokensPattern = this.getTokenStorageKey(userId, jti);
    await this.redisService.delete(tokensPattern);
    await this.revokeForApiGateway(jti);
  }

  async revokeApiToken(userId: string, tokenId: string): Promise<boolean> {
    const deletedToken = await this.apiTokenModel.findOneAndDelete({
      _id: tokenId,
      userId,
    });

    if (!deletedToken) {
      return false;
    }

    await this.revokeForApiGateway(deletedToken.jti);

    return true;
  }

  async revokeAllUserApiTokens(userId: string): Promise<boolean> {
    let jtis: string[];

    const session = await this.apiTokenModel.startSession();
    session.startTransaction();

    try {
      const userApiTokens = await this.apiTokenModel
        .find({ userId })
        .session(session);

      if (!userApiTokens.length) {
        await session.commitTransaction();
        session.endSession();
        return false;
      }

      await this.apiTokenModel.deleteMany({ userId }).session(session);

      await session.commitTransaction();
      session.endSession();

      jtis = userApiTokens.map((token) => token.jti);
    } catch (error) {
      await session.abortTransaction();
      session.endSession();

      throw error;
    }

    await this.revokeForApiGateway(jtis);

    return true;
  }

  async getTokenRedisStatus(
    userId: string,
    jti: string,
  ): Promise<TokenStatuses | null> {
    const tokenStorageKey = this.getTokenStorageKey(userId, jti);
    const redisValue = await this.redisService.get(tokenStorageKey);

    return redisValue ? (redisValue as TokenStatuses) : null;
  }
}
