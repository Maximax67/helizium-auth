import { Controller, HttpCode, Param, Post } from '@nestjs/common';
import { UserService } from './user.service';
import { ValidateMongoId } from '../../common/pipes';
import { TokenService } from '../tokens';
import { TokenStatuses } from '../../common/enums';

@Controller({ path: 'users', version: '1' })
export class UsersController {
  constructor(
    private readonly userService: UserService,
    private readonly tokenService: TokenService,
  ) {}

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
