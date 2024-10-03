import {
  Controller,
  Get,
  HttpCode,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { UserService } from './user.service';
import { ValidateMongoId } from '../../common/pipes';
import { TokenService } from '../tokens';
import { TokenStatuses } from '../../common/enums';
import { AuthorizedGuard } from '../../common/guards';
import { CurrentToken } from '../../common/decorators';
import { TokenInfo } from '../../common/interfaces';
import { Serialize } from '../../common/interceptors';
import { UserDto } from './dtos';

@Controller('users')
export class UsersController {
  constructor(
    private readonly userService: UserService,
    private readonly tokenService: TokenService,
  ) {}

  @Get('/me')
  @Serialize(UserDto)
  @UseGuards(AuthorizedGuard)
  async me(@CurrentToken() token: TokenInfo) {
    return this.userService.getUserById(token.userId);
  }

  @Post('/:userId/ban')
  @HttpCode(204)
  async ban(@Param('userId', ValidateMongoId) userId: string) {
    await this.userService.ban(userId);
    await this.tokenService.setAllUserTokensStatus(
      userId,
      TokenStatuses.UPDATE_REQUIRED,
    );
    await this.tokenService.revokeAllUserApiTokens(userId);
  }

  @Post('/:userId/unban')
  @HttpCode(204)
  async unban(@Param('userId', ValidateMongoId) userId: string) {
    await this.userService.unban(userId);
    await this.tokenService.setAllUserTokensStatus(
      userId,
      TokenStatuses.UPDATE_REQUIRED,
    );
  }

  @Post('/:userId/delete')
  @HttpCode(204)
  async delete(@Param('userId', ValidateMongoId) userId: string) {
    await this.userService.delete(userId);
    await this.tokenService.setAllUserTokensStatus(
      userId,
      TokenStatuses.UPDATE_REQUIRED,
    );
    await this.tokenService.revokeAllUserApiTokens(userId);
  }
}
