import {
  Controller,
  Post,
  Body,
  HttpCode,
  Get,
  Delete,
  UseGuards,
  Res,
  Req,
  VERSION_NEUTRAL,
} from '@nestjs/common';
import { FastifyReply, FastifyRequest } from 'fastify';

import { MfaService } from './mfa.service';
import { TokenInfo } from '../../common/interfaces';
import { Serialize } from '../../common/interceptors';
import { AuthorizedGuard, ForbidApiTokensGuard } from '../../common/guards';
import { MfaInfoResponseDto } from '../../common/dtos';
import { TokenLimits } from '../../common/enums';
import {
  ConfirmTotpDto,
  ConfirmEmailDto,
  ChangeMfaRequiredDto,
  UriDto,
} from './dtos';
import {
  CurrentToken,
  AllowedLimits,
  OptionalAuthorization,
} from '../../common/decorators';

@Controller({ path: 'auth/mfa', version: VERSION_NEUTRAL })
@UseGuards(AuthorizedGuard, ForbidApiTokensGuard)
export class MfaController {
  constructor(private readonly mfaService: MfaService) {}

  @Get()
  @Serialize(MfaInfoResponseDto)
  async getAvailableMfa(@CurrentToken() token: TokenInfo) {
    return this.mfaService.getAvailableMfa(token.userId);
  }

  @Post()
  @HttpCode(204)
  @AllowedLimits([TokenLimits.ROOT, TokenLimits.BANNED_ROOT])
  async changeMfaRequired(
    @Body() changeMfaRequiredDto: ChangeMfaRequiredDto,
    @CurrentToken() token: TokenInfo,
  ) {
    await this.mfaService.changeMfaRequired(
      token.userId,
      changeMfaRequiredDto.required,
    );
  }

  @Post('email/send-code')
  @AllowedLimits([
    TokenLimits.DEFAULT,
    TokenLimits.EMAIL_NOT_CONFIRMED,
    TokenLimits.MFA_REQUIRED,
  ])
  async sendEmailCode(
    @CurrentToken() token: TokenInfo,
    @Req() req: FastifyRequest,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    const { userId, limits } = token;
    await this.mfaService.sendEmailCode(req, res, userId, limits);
  }

  @Post('email/confirm')
  @OptionalAuthorization()
  @AllowedLimits([
    TokenLimits.DEFAULT,
    TokenLimits.EMAIL_NOT_CONFIRMED,
    TokenLimits.MFA_REQUIRED,
  ])
  @HttpCode(200)
  async confirmEmailCode(
    @Body() confirmEmailDto: ConfirmEmailDto,
    @CurrentToken() token: TokenInfo | null,
    @Req() req: FastifyRequest,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    if (!token) {
      await this.mfaService.confirmEmailCode(confirmEmailDto, req, res);
      return { isTokenVerifyRequired: true };
    }

    const isTokenVerifyRequired = await this.mfaService.confirmEmailCode(
      confirmEmailDto,
      req,
      res,
      token.userId,
      token.jti,
    );

    return { isTokenVerifyRequired };
  }

  @Delete('email/cancel')
  @AllowedLimits([
    TokenLimits.DEFAULT,
    TokenLimits.EMAIL_NOT_CONFIRMED,
    TokenLimits.MFA_REQUIRED,
  ])
  @HttpCode(204)
  async cancelEmailConfirmation(
    @CurrentToken() token: TokenInfo,
    @Req() req: FastifyRequest,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    await this.mfaService.cancelEmailConfirmation(req, res, token.userId);
  }

  @Get('email/verify')
  @AllowedLimits([
    TokenLimits.DEFAULT,
    TokenLimits.EMAIL_NOT_CONFIRMED,
    TokenLimits.MFA_REQUIRED,
  ])
  async verifyEmailConfirmation(
    @CurrentToken() token: TokenInfo,
    @Req() req: FastifyRequest,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    const { userId, jti } = token;
    const confirmed = await this.mfaService.verifyEmailConfirm(
      req,
      res,
      userId,
      jti,
    );

    return { confirmed };
  }

  @Delete('totp')
  @AllowedLimits([TokenLimits.ROOT, TokenLimits.BANNED_ROOT])
  @HttpCode(204)
  async disableTotp(@CurrentToken() token: TokenInfo) {
    await this.mfaService.disableTotp(token.userId);
  }

  @Post('totp/init')
  @AllowedLimits([TokenLimits.ROOT, TokenLimits.BANNED_ROOT])
  @Serialize(UriDto)
  async initTotp(@CurrentToken() token: TokenInfo) {
    const uri = await this.mfaService.initTotp(token.userId);
    return { uri };
  }

  @Post('totp/confirm')
  @AllowedLimits([
    TokenLimits.DEFAULT,
    TokenLimits.EMAIL_NOT_CONFIRMED,
    TokenLimits.MFA_REQUIRED,
    TokenLimits.ROOT,
    TokenLimits.BANNED_ROOT,
  ])
  @HttpCode(204)
  async confirmTotp(
    @Body() confirmTotpDto: ConfirmTotpDto,
    @CurrentToken() token: TokenInfo,
  ) {
    const { userId, limits, jti } = token;
    await this.mfaService.confirmTotp(
      userId,
      limits,
      jti,
      confirmTotpDto.token,
    );
  }
}
