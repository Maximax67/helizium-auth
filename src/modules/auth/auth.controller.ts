import {
  Controller,
  Post,
  Body,
  HttpCode,
  UseGuards,
  Req,
  Res,
  Get,
} from '@nestjs/common';
import { FastifyRequest, FastifyReply } from 'fastify';

import { AuthService } from './auth.service';
import { JwksDto, TokenInfoDto } from './dtos';
import { MfaInfoResponseDto, SignInDto, SignUpDto } from '../../common/dtos';
import { AuthorizedGuard, ForbidApiTokensGuard } from '../../common/guards';
import { CurrentToken } from '../../common/decorators';
import { TokenInfo } from '../../common/interfaces';
import { Serialize } from '../../common/interceptors';

@Controller('auth')
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
    return await this.authService.sign(signInDto, res);
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
}
