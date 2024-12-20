import {
  Controller,
  Post,
  Body,
  HttpCode,
  UseGuards,
  Req,
  Res,
  Get,
  VERSION_NEUTRAL,
} from '@nestjs/common';
import { FastifyRequest, FastifyReply } from 'fastify';

import { AuthService } from './auth.service';
import {
  ChangePasswordDto,
  JwksDto,
  LostPasswordChangeDto,
  LostPasswordDto,
  LostPasswordVerifyDto,
  TokenInfoDto,
} from './dtos';
import { MfaInfoResponseDto, SignInDto, SignUpDto } from '../../common/dtos';
import { AuthorizedGuard, ForbidApiTokensGuard } from '../../common/guards';
import { AllowedLimits, CurrentToken } from '../../common/decorators';
import { TokenInfo } from '../../common/interfaces';
import { Serialize } from '../../common/interceptors';
import { TokenLimits } from '../../common/enums';
import { ApiError } from '../../common/errors';
import { Errors } from '../../common/constants';

@Controller({ path: 'auth', version: VERSION_NEUTRAL })
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('/jwks')
  @Serialize(JwksDto)
  async returnJwks() {
    return this.authService.returnJwks();
  }

  @Post('/signup')
  async signup(
    @Body() signUpDto: SignUpDto,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    await this.authService.signup(signUpDto, res);
  }

  @Post('/sign')
  @HttpCode(200)
  @Serialize(MfaInfoResponseDto)
  async sign(
    @Body() signInDto: SignInDto,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    return this.authService.sign(signInDto, res);
  }

  @Get('/info')
  @UseGuards(AuthorizedGuard)
  @Serialize(TokenInfoDto)
  info(@CurrentToken() token: TokenInfo) {
    return token;
  }

  @Post('/refresh')
  @HttpCode(200)
  async refresh(
    @Req() req: FastifyRequest,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    await this.authService.refresh(req, res);
  }

  @Post('/logout')
  @UseGuards(AuthorizedGuard, ForbidApiTokensGuard)
  @HttpCode(204)
  async logout(
    @CurrentToken() token: TokenInfo,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    const { userId, jti } = token;
    await this.authService.logout(res, userId, jti);
  }

  @Post('/terminate')
  @UseGuards(AuthorizedGuard, ForbidApiTokensGuard)
  @HttpCode(204)
  async terminate(
    @CurrentToken() token: TokenInfo,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    await this.authService.terminate(res, token.userId);
  }

  @Post('/lost-password/send-email')
  async lostPasswordSendEmail(@Body() lostPasswordDto: LostPasswordDto) {
    const email = lostPasswordDto.email;
    await this.authService.requestPasswordChange(email);
  }

  @Post('/lost-password/verify')
  @HttpCode(204)
  async lostPasswordVerify(
    @Body() lostPasswordVerifyDto: LostPasswordVerifyDto,
  ) {
    const { userId, token } = lostPasswordVerifyDto;
    await this.authService.verifyPasswordChangeToken(userId, token);
  }

  @Post('/lost-password/change')
  async lostPassword(
    @Body() lostPasswordChangeDto: LostPasswordChangeDto,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    const { userId, token, password } = lostPasswordChangeDto;
    await this.authService.confirmPasswordChange(res, userId, token, password);
  }

  @Post('/change-password')
  @UseGuards(AuthorizedGuard, ForbidApiTokensGuard)
  @AllowedLimits([TokenLimits.ROOT, TokenLimits.BANNED_ROOT])
  async changePassword(
    @CurrentToken() token: TokenInfo,
    @Body() changePassword: ChangePasswordDto,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    const { newPassword, oldPassword } = changePassword;
    if (newPassword === oldPassword) {
      throw new ApiError(Errors.NEW_PASSWORD_FIELD_SAME_WITH_OLD);
    }

    await this.authService.changeUserPassword(
      res,
      token.userId,
      oldPassword,
      newPassword,
    );
  }
}
