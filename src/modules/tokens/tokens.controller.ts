import {
  Controller,
  Post,
  Body,
  HttpCode,
  UseGuards,
  Get,
  Param,
  Delete,
  VERSION_NEUTRAL,
} from '@nestjs/common';
import { TokenService } from './token.service';
import { TokenInfo } from '../../common/interfaces';
import { Serialize } from '../../common/interceptors';
import { AllowedLimits, CurrentToken } from '../../common/decorators';
import { AuthorizedGuard, ForbidApiTokensGuard } from '../../common/guards';
import { TokenLimits } from '../../common/enums';
import {
  ApiTokenDto,
  ApiTokensListDto,
  CreateApiTokenDto,
  JtiDto,
} from './dtos';
import { ApiError } from '../../common/errors';

@Controller({ path: 'auth/api-tokens', version: VERSION_NEUTRAL })
export class TokensController {
  constructor(private readonly tokenService: TokenService) {}

  @Post('/validate')
  @HttpCode(200)
  async validate(@Body() jtiDto: JtiDto) {
    const jti = jtiDto.jti;
    const result = await this.tokenService.validateApiToken(jti);
    if (!result) {
      await this.tokenService.revokeForApiGateway(jti);

      // TODO Move to error templates
      throw new ApiError({
        id: 'REVOKED_API_TOKEN',
        message: 'API token was revoked',
        status: 403,
      });
    }
  }

  @Get()
  @UseGuards(AuthorizedGuard, ForbidApiTokensGuard)
  @AllowedLimits([TokenLimits.ROOT, TokenLimits.BANNED_ROOT])
  @Serialize(ApiTokensListDto)
  async getApiTokens(@CurrentToken() token: TokenInfo) {
    const tokens = await this.tokenService.getUserApiTokens(token.userId);
    return { tokens };
  }

  @Delete()
  @UseGuards(AuthorizedGuard, ForbidApiTokensGuard)
  @AllowedLimits([TokenLimits.ROOT, TokenLimits.BANNED_ROOT])
  @HttpCode(204)
  async revokeAllUserApiTokens(@CurrentToken() token: TokenInfo) {
    if (!(await this.tokenService.revokeAllUserApiTokens(token.userId))) {
      throw new Error('User does not have any API tokens');
    }
  }

  @Post()
  @UseGuards(AuthorizedGuard, ForbidApiTokensGuard)
  @AllowedLimits([TokenLimits.ROOT, TokenLimits.BANNED_ROOT])
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

  @Get('/:jti')
  @UseGuards(AuthorizedGuard, ForbidApiTokensGuard)
  @AllowedLimits([TokenLimits.ROOT, TokenLimits.BANNED_ROOT])
  @Serialize(ApiTokenDto)
  async getApiToken(
    @Param('jti') jti: string,
    @CurrentToken() token: TokenInfo,
  ) {
    return this.tokenService.getUserApiToken(token.userId, jti);
  }

  @Delete('/:jti')
  @UseGuards(AuthorizedGuard, ForbidApiTokensGuard)
  @AllowedLimits([TokenLimits.ROOT, TokenLimits.BANNED_ROOT])
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
