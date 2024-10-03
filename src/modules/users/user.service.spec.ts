import { Test, TestingModule } from '@nestjs/testing';
import { UserService } from './user.service';
import { HashService } from './hash.service';
import { SignInDto, SignUpDto } from '../../common/dtos';
import { TokenLimits } from '../../common/enums';

// TODO Remove dependency from mongoose, switch to typeorm
class ObjectId {
  public id;

  constructor() {
    this.id = '507f1f77bcf86cd799439011';
  }

  toString() {
    return this.id;
  }
}
const Types = {
  ObjectId: ObjectId,
};

interface MongoError extends Error {
  code: number;
}

describe('UserService', () => {
  let userService: UserService;
  let hashService: HashService;

  const mockUserModel = {
    create: jest.fn(),
    findById: jest.fn(),
    findOne: jest.fn(),
    findByIdAndUpdate: jest.fn(),
    findOneAndUpdate: jest.fn(),
    lean: jest.fn(),
    exec: jest.fn(),
  };

  const mockHashService = {
    hashData: jest.fn(),
    compareHash: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserService,
        { provide: HashService, useValue: mockHashService },
        { provide: '1234', useValue: mockUserModel }, // TODO Fix
      ],
    }).compile();

    userService = module.get<UserService>(UserService);
    hashService = module.get<HashService>(HashService);
  });

  it('should be defined', () => {
    expect(userService).toBeDefined();
  });

  describe('UserService', () => {
    it('should define createUser()', () => {
      expect(userService.createUser).toBeDefined();
      expect(typeof userService.createUser).toBe('function');
    });

    it('should define getUserEmailAndUsername()', () => {
      expect(userService.getUserEmailAndUsername).toBeDefined();
      expect(typeof userService.getUserEmailAndUsername).toBe('function');
    });

    it('should define verifyUser()', () => {
      expect(userService.verifyUser).toBeDefined();
      expect(typeof userService.verifyUser).toBe('function');
    });

    it('should define isUserHasLimits()', () => {
      expect(userService.isUserHasLimits).toBeDefined();
      expect(typeof userService.isUserHasLimits).toBe('function');
    });

    it('should define getUserLimitsIfBecameRoot()', () => {
      expect(userService.getUserLimitsIfBecameRoot).toBeDefined();
      expect(typeof userService.getUserLimitsIfBecameRoot).toBe('function');
    });

    it('should define confirmEmailIfNotConfirmed()', () => {
      expect(userService.confirmEmailIfNotConfirmed).toBeDefined();
      expect(typeof userService.confirmEmailIfNotConfirmed).toBe('function');
    });

    it('should define getUserMfaInfo()', () => {
      expect(userService.getUserMfaInfo).toBeDefined();
      expect(typeof userService.getUserMfaInfo).toBe('function');
    });

    it('should define changeMfaRequired()', () => {
      expect(userService.changeMfaRequired).toBeDefined();
      expect(typeof userService.changeMfaRequired).toBe('function');
    });

    it('should define disableTotpMfa()', () => {
      expect(userService.disableTotpMfa).toBeDefined();
      expect(typeof userService.disableTotpMfa).toBe('function');
    });

    it('should define setTotpSecret()', () => {
      expect(userService.setTotpSecret).toBeDefined();
      expect(typeof userService.setTotpSecret).toBe('function');
    });

    it('should define getTotpSecret()', () => {
      expect(userService.getTotpSecret).toBeDefined();
      expect(typeof userService.getTotpSecret).toBe('function');
    });
  });

  describe('createUser', () => {
    it('should create a user and return the user ID', async () => {
      const signUpDto: SignUpDto = {
        username: 'test',
        email: 'test@example.com',
        password: 'password123',
      };
      const userId = new Types.ObjectId();

      mockHashService.hashData.mockResolvedValue('hashedPassword');
      mockUserModel.create.mockResolvedValue({ _id: userId });

      const result = await userService.createUser(signUpDto);

      expect(hashService.hashData).toHaveBeenCalledWith(signUpDto.password);
      expect(mockUserModel.create).toHaveBeenCalledWith({
        username: signUpDto.username,
        email: signUpDto.email,
        passwordHash: 'hashedPassword',
      });
      expect(result).toEqual(userId);
    });

    it('should throw an error if user already exists', async () => {
      const error = new Error() as MongoError;
      error.code = 11000;

      mockUserModel.create.mockRejectedValue(error);

      const signUpDto: SignUpDto = {
        username: 'test',
        email: 'test@example.com',
        password: 'password123',
      };

      await expect(userService.createUser(signUpDto)).rejects.toThrow();
    });

    it('should throw a generic error if another database error occurs', async () => {
      const error = new Error('Database error');
      mockUserModel.create.mockRejectedValue(error);

      const signUpDto: SignUpDto = {
        username: 'test',
        email: 'test@example.com',
        password: 'password123',
      };

      await expect(userService.createUser(signUpDto)).rejects.toThrow(
        'Database error',
      );
    });
  });

  describe('getUserEmailAndUsername', () => {
    it('should return the user for a given ID', async () => {
      const userId = new Types.ObjectId().toString();
      const mockUser = { _id: userId, username: 'testUser' };

      mockUserModel.findById.mockReturnThis();
      mockUserModel.lean.mockResolvedValue(mockUser);

      const result = await userService.getUserEmailAndUsername(userId);

      expect(mockUserModel.findById).toHaveBeenCalledWith(userId, undefined);
      expect(result).toEqual(mockUser);
    });

    it('should return null if user not found', async () => {
      mockUserModel.findById.mockReturnThis();
      mockUserModel.lean.mockResolvedValue(null);

      const result =
        await userService.getUserEmailAndUsername('nonexistentUserId');

      expect(result).toBeNull();
    });
  });

  describe('verifyUser', () => {
    it('should return a verified user with limits and MFA info', async () => {
      const signInDto: SignInDto = {
        login: 'testUser',
        password: 'password123',
      };
      const mockUser = {
        _id: new Types.ObjectId(),
        passwordHash: 'hashedPassword',
        isEmailConfirmed: true,
        isBanned: false,
        mfaRequired: false,
        totpSecret: 'secret',
      };

      mockUserModel.findOne.mockReturnThis();
      mockUserModel.lean.mockResolvedValue(mockUser);
      mockHashService.compareHash.mockResolvedValueOnce(true);

      const result = await userService.verifyUser(signInDto);

      expect(mockUserModel.findOne).toHaveBeenCalledWith(
        { username: signInDto.login },
        expect.any(Object),
      );
      expect(hashService.compareHash).toHaveBeenCalledWith(
        signInDto.password,
        mockUser.passwordHash,
      );
      expect(result).toEqual({
        userId: mockUser._id,
        limits: TokenLimits.DEFAULT,
        mfa: { required: false, methods: ['EMAIL', 'TOTP'] },
      });
    });

    it('should return null if user verification fails', async () => {
      const signInDto: SignInDto = {
        login: 'testUser',
        password: 'wrongPassword',
      };

      mockUserModel.findOne.mockReturnThis();
      mockUserModel.lean.mockResolvedValueOnce(null);

      const result = await userService.verifyUser(signInDto);

      expect(result).toBeNull();
    });

    it('should return null if password hash comparison fails', async () => {
      const signInDto: SignInDto = {
        login: 'testUser',
        password: 'password123',
      };
      const mockUser = {
        _id: new Types.ObjectId(),
        passwordHash: 'hashedPassword',
        isEmailConfirmed: true,
        isBanned: false,
        mfaRequired: false,
        totpSecret: 'secret',
      };

      mockUserModel.findOne.mockReturnThis();
      mockUserModel.lean.mockResolvedValue(mockUser);
      mockHashService.compareHash.mockResolvedValueOnce(false);

      const result = await userService.verifyUser(signInDto);

      expect(result).toBeNull();
    });
  });

  describe('confirmEmailIfNotConfirmed', () => {
    it('should confirm email if it is not confirmed', async () => {
      const userId = new Types.ObjectId().toString();
      mockUserModel.findOneAndUpdate.mockResolvedValueOnce({ _id: userId });

      const result = await userService.confirmEmailIfNotConfirmed(userId);

      expect(mockUserModel.findOneAndUpdate).toHaveBeenCalledWith(
        { _id: userId, isEmailConfirmed: false },
        { $set: { isEmailConfirmed: true } },
      );
      expect(result).toBe(true);
    });

    it('should return false if user is already confirmed', async () => {
      mockUserModel.findOneAndUpdate.mockResolvedValueOnce(null);

      const result = await userService.confirmEmailIfNotConfirmed(
        new Types.ObjectId().toString(),
      );

      expect(result).toBe(false);
    });

    it('should confirm email and return true when email is not confirmed', async () => {
      const userId = new Types.ObjectId().toString();

      mockUserModel.findOneAndUpdate.mockResolvedValueOnce({ _id: userId });

      const result = await userService.confirmEmailIfNotConfirmed(userId);

      expect(mockUserModel.findOneAndUpdate).toHaveBeenCalledWith(
        { _id: userId, isEmailConfirmed: false },
        { $set: { isEmailConfirmed: true } },
      );
      expect(result).toBe(true);
    });
  });

  describe('isUserHasLimits', () => {
    it('should return USER_BANNED if user is banned', async () => {
      const userId = new Types.ObjectId().toString();
      const mockUser = { isBanned: true, isEmailConfirmed: true };

      mockUserModel.findById.mockReturnThis();
      mockUserModel.lean.mockResolvedValue(mockUser);

      const result = await userService.isUserHasLimits(userId);

      expect(result).toBe(TokenLimits.USER_BANNED);
    });

    it('should return EMAIL_NOT_CONFIRMED if email is not confirmed', async () => {
      const userId = new Types.ObjectId().toString();
      const mockUser = { isBanned: false, isEmailConfirmed: false };

      mockUserModel.findById.mockReturnThis();
      mockUserModel.lean.mockResolvedValue(mockUser);

      const result = await userService.isUserHasLimits(userId);

      expect(result).toBe(TokenLimits.EMAIL_NOT_CONFIRMED);
    });

    it('should return DEFAULT if user has no limits', async () => {
      const userId = new Types.ObjectId().toString();
      const mockUser = { isBanned: false, isEmailConfirmed: true };

      mockUserModel.findById.mockReturnThis();
      mockUserModel.lean.mockResolvedValue(mockUser);

      const result = await userService.isUserHasLimits(userId);

      expect(result).toBe(TokenLimits.DEFAULT);
    });

    it('should return null if user is not found', async () => {
      mockUserModel.findById.mockReturnThis();
      mockUserModel.lean.mockResolvedValue(null);

      const result = await userService.isUserHasLimits('nonexistentUserId');

      expect(result).toBeNull();
    });

    it('should call findById with the correct projection', async () => {
      const userId = new Types.ObjectId().toString();
      const mockUser = { isBanned: true, isEmailConfirmed: true };

      mockUserModel.findById.mockReturnThis();
      mockUserModel.lean.mockResolvedValue(mockUser);

      await userService.isUserHasLimits(userId);

      expect(mockUserModel.findById).toHaveBeenCalledWith(userId, {
        isEmailConfirmed: 1,
        isBanned: 1,
      });
    });
  });

  describe('disableTotpMfa', () => {
    it('should set totpSecret to null for a given user', async () => {
      const userId = new Types.ObjectId().toString();

      await userService.disableTotpMfa(userId);

      expect(mockUserModel.findByIdAndUpdate).toHaveBeenCalledWith(userId, {
        $set: { totpSecret: null },
      });
    });
  });

  describe('setTotpSecret', () => {
    it('should set totpSecret for a given user', async () => {
      const userId = new Types.ObjectId().toString();
      const secret = 'newTotpSecret';

      await userService.setTotpSecret(userId, secret);

      expect(mockUserModel.findByIdAndUpdate).toHaveBeenCalledWith(userId, {
        $set: { totpSecret: secret },
      });
    });
  });

  describe('getTotpSecret', () => {
    it('should return the totpSecret for a valid user', async () => {
      const userId = new Types.ObjectId().toString();
      const mockUser = { totpSecret: 'secret' };

      mockUserModel.findById.mockResolvedValue(mockUser);

      const result = await userService.getTotpSecret(userId);

      expect(mockUserModel.findById).toHaveBeenCalledWith(userId, {
        totpSecret: 1,
      });
      expect(result).toEqual('secret');
    });

    it('should return null if totpSecret is not set', async () => {
      const userId = new Types.ObjectId().toString();
      const mockUser = { totpSecret: null };

      mockUserModel.findById.mockResolvedValue(mockUser);

      const result = await userService.getTotpSecret(userId);

      expect(result).toBeNull();
    });

    it('should throw an error if user is not found', async () => {
      mockUserModel.findById.mockResolvedValue(null);

      await expect(
        userService.getTotpSecret('nonexistentUserId'),
      ).rejects.toThrow('User not found');
    });
  });
});
