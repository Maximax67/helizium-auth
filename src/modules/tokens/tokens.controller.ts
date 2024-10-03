import {
  Controller,
  Post,
  Body,
  HttpCode,
  UseGuards,
  Get,
  Param,
  Delete,
} from '@nestjs/common';
import { TokenService } from './token.service';
import { TokenInfo } from '../../common/interfaces';
import { Serialize } from '../../common/interceptors';
import { AllowedLimits, CurrentToken } from '../../common/decorators';
import { AuthorizedGuard, ForbidApiTokensGuard } from '../../common/guards';
import { TokenLimits } from '../../common/enums';
import { ApiTokenDto, ApiTokensListDto, CreateApiTokenDto } from './dtos';

@Controller('auth/api-tokens')
@UseGuards(AuthorizedGuard, ForbidApiTokensGuard)
@AllowedLimits([TokenLimits.ROOT, TokenLimits.BANNED_ROOT])
export class TokensController {
  constructor(private readonly tokenService: TokenService) {}

  @Get()
  @Serialize(ApiTokensListDto)
  async getApiTokens(@CurrentToken() token: TokenInfo) {
    const tokens = await this.tokenService.getUserApiTokens(token.userId);
    return { tokens };
  }

  @Delete()
  @HttpCode(204)
  async revokeAllUserApiTokens(@CurrentToken() token: TokenInfo) {
    if (!(await this.tokenService.revokeAllUserApiTokens(token.userId))) {
      throw new Error('User does not have any API tokens');
    }
  }

  @Post()
  async createApiToken(
    @Body() createApiTokenDto: CreateApiTokenDto,
    @CurrentToken() token: TokenInfo,
  ) {
    const { title, writeAccess } = createApiTokenDto;
    const apiToken = await this.tokenService.generateApiToken(
      token.userId,
      title,
      writeAccess,
    );

    return { token: apiToken };
  }

  @Serialize(ApiTokenDto)
  @Get('/:jti')
  async getApiToken(
    @Param('jti') jti: string,
    @CurrentToken() token: TokenInfo,
  ) {
    return this.tokenService.getUserApiToken(token.userId, jti);
  }

  @Delete('/:jti')
  @HttpCode(204)
  async revokeApiToken(
    @Param('jti') jti: string,
    @CurrentToken() token: TokenInfo,
  ) {
    if (!(await this.tokenService.revokeApiToken(token.userId, jti))) {
      throw new Error('Api token not found');
    }
  }
}
