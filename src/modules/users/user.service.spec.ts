import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { UserService } from './user.service';
import { HashService } from './hash.service';
import { User } from './entities';
import { SignUpDto, SignInDto } from '../../common/dtos';
import { ClientGrpc } from '@nestjs/microservices';
import { Repository } from 'typeorm';
import { of } from 'rxjs';
import { MfaMethods, TokenLimits } from '../../common/enums';
import { Errors } from '../../common/constants';

const mockUserRepository = () => ({
  findOne: jest.fn(),
  findOneBy: jest.fn(),
  insert: jest.fn(),
  update: jest.fn(),
  manager: {
    connection: {
      createQueryRunner: jest.fn().mockReturnValue({
        startTransaction: jest.fn(),
        manager: { update: jest.fn() },
        commitTransaction: jest.fn(),
        rollbackTransaction: jest.fn(),
        release: jest.fn(),
      }),
    },
  },
});

const mockHashService = () => ({
  hashData: jest.fn(),
  compareHash: jest.fn(),
});

const mockGrpcClient = () => ({
  getService: jest.fn().mockReturnValue({
    signUp: jest.fn(),
    unbanUser: jest.fn(),
    deleteUser: jest.fn(),
  }),
});

describe('UserService', () => {
  let userService: UserService;
  let userRepository: Repository<User>;
  let hashService: HashService;
  let grpcClient: ClientGrpc;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserService,
        { provide: getRepositoryToken(User), useFactory: mockUserRepository },
        { provide: HashService, useFactory: mockHashService },
        { provide: 'USERS_PACKAGE', useFactory: mockGrpcClient },
      ],
    }).compile();

    userService = module.get<UserService>(UserService);
    userRepository = module.get<Repository<User>>(getRepositoryToken(User));
    hashService = module.get<HashService>(HashService);
    grpcClient = module.get<ClientGrpc>('USERS_PACKAGE');

    const mockUsersServiceClient = {
      signUp: jest.fn().mockReturnValue(of({ userId: '123' })),
    };
    grpcClient.getService = jest.fn().mockReturnValue(mockUsersServiceClient);

    userService.onModuleInit();
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
    it('should throw an error if user already exists and is not deleted', async () => {
      (userRepository.findOne as jest.Mock).mockResolvedValue({
        isDeleted: false,
      });

      const signUpDto: SignUpDto = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password',
      };

      await expect(userService.createUser(signUpDto)).rejects.toThrow(
        Errors.USER_ALREADY_EXISTS.message,
      );
    });

    it('should throw an error if user exists but was previously deleted', async () => {
      (userRepository.findOne as jest.Mock).mockResolvedValue({
        isDeleted: true,
      });

      const signUpDto: SignUpDto = {
        username: 'deleteduser',
        email: 'deleted@example.com',
        password: 'password',
      };

      await expect(userService.createUser(signUpDto)).rejects.toThrow(
        Errors.USER_DELETED.message,
      );
    });

    it('should successfully create a new user', async () => {
      (userRepository.findOne as jest.Mock).mockResolvedValue(null);

      (hashService.hashData as jest.Mock).mockResolvedValue('hashedPassword');

      const signUpDto: SignUpDto = {
        username: 'newuser',
        email: 'new@example.com',
        password: 'password',
      };

      const userId = await userService.createUser(signUpDto);

      expect(userId).toBe('123');
      expect(userRepository.insert).toHaveBeenCalledWith({
        id: Buffer.from('123', 'hex'),
        username: 'newuser',
        email: 'new@example.com',
        passwordHash: 'hashedPassword',
      });
    });
  });

  describe('getUserEmailAndUsername', () => {
    it('should return user email and username if user is found', async () => {
      const mockUser = { email: 'test@example.com', username: 'testuser' };

      (userRepository.findOne as jest.Mock).mockResolvedValue(mockUser);

      const result = await userService.getUserEmailAndUsername('123');

      expect(result).toEqual(mockUser);
      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: Buffer.from('123', 'hex') },
        select: ['email', 'username'],
      });
    });

    it('should return null if user is not found', async () => {
      (userRepository.findOne as jest.Mock).mockResolvedValue(null);

      const result = await userService.getUserEmailAndUsername('123');

      expect(result).toBeNull();
      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: Buffer.from('123', 'hex') },
        select: ['email', 'username'],
      });
    });
  });

  describe('verifyUser', () => {
    it('should return null if user is not found', async () => {
      (userRepository.findOne as jest.Mock).mockResolvedValue(null);

      const signInData: SignInDto = {
        login: 'nonexistentuser',
        password: 'password',
      };

      const result = await userService.verifyUser(signInData);

      expect(result).toBeNull();
      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { username: 'nonexistentuser', isDeleted: false },
        select: [
          'id',
          'passwordHash',
          'isEmailConfirmed',
          'isBanned',
          'isMfaRequired',
          'totpSecret',
        ],
      });
    });

    it('should return null if password does not match', async () => {
      const mockUser = {
        id: Buffer.from('123', 'hex'),
        passwordHash: 'hashedPassword',
        isEmailConfirmed: true,
        isBanned: false,
        isMfaRequired: false,
        totpSecret: null,
      };

      (userRepository.findOne as jest.Mock).mockResolvedValue(mockUser);
      (hashService.compareHash as jest.Mock).mockResolvedValue(false);

      const signInData: SignInDto = {
        login: 'testuser',
        password: 'wrongpassword',
      };

      const result = await userService.verifyUser(signInData);

      expect(result).toBeNull();
      expect(hashService.compareHash).toHaveBeenCalledWith(
        'wrongpassword',
        'hashedPassword',
      );
    });

    it('should return user with default limits if password matches and no special limits apply', async () => {
      const mockUser = {
        id: Buffer.from('123', 'hex'),
        passwordHash: 'hashedPassword',
        isEmailConfirmed: true,
        isBanned: false,
        isMfaRequired: false,
        totpSecret: null,
      };

      (userRepository.findOne as jest.Mock).mockResolvedValue(mockUser);
      (hashService.compareHash as jest.Mock).mockResolvedValue(true);

      const signInData: SignInDto = {
        login: 'testuser',
        password: 'correctpassword',
      };

      const result = await userService.verifyUser(signInData);

      expect(result).toEqual({
        userId: mockUser.id.toString('hex'),
        limits: TokenLimits.DEFAULT,
        mfa: { required: false, methods: [MfaMethods.EMAIL] },
      });
    });

    it('should return user with MFA_REQUIRED if MFA is required', async () => {
      const mockUser = {
        id: Buffer.from('123', 'hex'),
        passwordHash: 'hashedPassword',
        isEmailConfirmed: true,
        isBanned: false,
        isMfaRequired: true,
        totpSecret: 'someTotpSecret',
      };

      (userRepository.findOne as jest.Mock).mockResolvedValue(mockUser);
      (hashService.compareHash as jest.Mock).mockResolvedValue(true);

      const signInData: SignInDto = {
        login: 'testuser',
        password: 'correctpassword',
      };

      const result = await userService.verifyUser(signInData);

      expect(result).toEqual({
        userId: mockUser.id.toString('hex'),
        limits: TokenLimits.MFA_REQUIRED,
        mfa: { required: true, methods: [MfaMethods.EMAIL, MfaMethods.TOTP] },
      });
    });

    it('should return USER_BANNED if user is banned', async () => {
      const mockUser = {
        id: Buffer.from('123', 'hex'),
        passwordHash: 'hashedPassword',
        isEmailConfirmed: true,
        isBanned: true,
        isMfaRequired: false,
        totpSecret: null,
      };

      (userRepository.findOne as jest.Mock).mockResolvedValue(mockUser);
      (hashService.compareHash as jest.Mock).mockResolvedValue(true);

      const signInData: SignInDto = {
        login: 'testuser',
        password: 'correctpassword',
      };

      const result = await userService.verifyUser(signInData);

      expect(result).toEqual({
        userId: mockUser.id.toString('hex'),
        limits: TokenLimits.USER_BANNED,
        mfa: { required: false, methods: [MfaMethods.EMAIL] },
      });
    });

    it('should return EMAIL_NOT_CONFIRMED if email is not confirmed', async () => {
      const mockUser = {
        id: Buffer.from('123', 'hex'),
        passwordHash: 'hashedPassword',
        isEmailConfirmed: false,
        isBanned: false,
        isMfaRequired: false,
        totpSecret: null,
      };

      (userRepository.findOne as jest.Mock).mockResolvedValue(mockUser);
      (hashService.compareHash as jest.Mock).mockResolvedValue(true);

      const signInData: SignInDto = {
        login: 'testuser',
        password: 'correctpassword',
      };

      const result = await userService.verifyUser(signInData);

      expect(result).toEqual({
        userId: mockUser.id.toString('hex'),
        limits: TokenLimits.EMAIL_NOT_CONFIRMED,
        mfa: { required: false, methods: [MfaMethods.EMAIL] },
      });
    });
  });

  describe('isUserHasLimits', () => {
    it('should return null if user is not found', async () => {
      (userRepository.findOne as jest.Mock).mockResolvedValue(null);

      const result = await userService.isUserHasLimits('123');

      expect(result).toBeNull();
      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: Buffer.from('123', 'hex'), isDeleted: false },
        select: ['isBanned', 'isEmailConfirmed'],
      });
    });

    it('should return USER_BANNED if user is banned', async () => {
      const mockUser = { isBanned: true, isEmailConfirmed: true };

      (userRepository.findOne as jest.Mock).mockResolvedValue(mockUser);

      const result = await userService.isUserHasLimits('123');

      expect(result).toBe(TokenLimits.USER_BANNED);
      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: Buffer.from('123', 'hex'), isDeleted: false },
        select: ['isBanned', 'isEmailConfirmed'],
      });
    });

    it("should return EMAIL_NOT_CONFIRMED if user's email is not confirmed", async () => {
      const mockUser = { isBanned: false, isEmailConfirmed: false };

      (userRepository.findOne as jest.Mock).mockResolvedValue(mockUser);

      const result = await userService.isUserHasLimits('123');

      expect(result).toBe(TokenLimits.EMAIL_NOT_CONFIRMED);
      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: Buffer.from('123', 'hex'), isDeleted: false },
        select: ['isBanned', 'isEmailConfirmed'],
      });
    });

    it('should return DEFAULT if user has no limits', async () => {
      const mockUser = { isBanned: false, isEmailConfirmed: true };

      (userRepository.findOne as jest.Mock).mockResolvedValue(mockUser);

      const result = await userService.isUserHasLimits('123');

      expect(result).toBe(TokenLimits.DEFAULT);
      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: Buffer.from('123', 'hex'), isDeleted: false },
        select: ['isBanned', 'isEmailConfirmed'],
      });
    });
  });

  describe('getUserLimitsIfBecameRoot', () => {
    let isUserHasLimits: jest.SpyInstance;

    beforeEach(async () => {
      isUserHasLimits = jest.spyOn(userService, 'isUserHasLimits');
    });

    it('should return null if isUserHasLimits returns null', async () => {
      isUserHasLimits.mockResolvedValue(null);

      const result = await userService.getUserLimitsIfBecameRoot('123');

      expect(result).toBeNull();
      expect(isUserHasLimits).toHaveBeenCalledWith('123');
    });

    it('should return BANNED_ROOT if user is banned', async () => {
      isUserHasLimits.mockResolvedValue(TokenLimits.USER_BANNED);

      const result = await userService.getUserLimitsIfBecameRoot('123');

      expect(result).toBe(TokenLimits.BANNED_ROOT);
      expect(isUserHasLimits).toHaveBeenCalledWith('123');
    });

    it('should return ROOT if user has no significant limits', async () => {
      isUserHasLimits.mockResolvedValue(TokenLimits.DEFAULT);

      const result = await userService.getUserLimitsIfBecameRoot('123');

      expect(result).toBe(TokenLimits.ROOT);
      expect(isUserHasLimits).toHaveBeenCalledWith('123');
    });
  });

  describe('confirmEmailIfNotConfirmed', () => {
    it('should return true if email confirmation is successful', async () => {
      (userRepository.update as jest.Mock).mockResolvedValue({ affected: 1 });

      const result = await userService.confirmEmailIfNotConfirmed('123');

      expect(result).toBe(true);
      expect(userRepository.update).toHaveBeenCalledWith(
        { id: Buffer.from('123', 'hex'), isEmailConfirmed: false },
        { isEmailConfirmed: true },
      );
    });

    it('should return false if email was already confirmed (no rows affected)', async () => {
      (userRepository.update as jest.Mock).mockResolvedValue({ affected: 0 });

      const result = await userService.confirmEmailIfNotConfirmed('123');

      expect(result).toBe(false);
      expect(userRepository.update).toHaveBeenCalledWith(
        { id: Buffer.from('123', 'hex'), isEmailConfirmed: false },
        { isEmailConfirmed: true },
      );
    });
  });

  describe('getUserMfaInfo', () => {
    it('should throw an error if the user is not found', async () => {
      (userRepository.findOne as jest.Mock).mockResolvedValue(null);

      await expect(userService.getUserMfaInfo('123')).rejects.toThrow(
        Errors.USER_NOT_FOUND.message,
      );

      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: Buffer.from('123', 'hex'), isDeleted: false },
        select: ['isMfaRequired', 'totpSecret'],
      });
    });

    it('should return MFA info when user has MFA disabled', async () => {
      const mockUser = { isMfaRequired: false, totpSecret: null };

      (userRepository.findOne as jest.Mock).mockResolvedValue(mockUser);

      const result = await userService.getUserMfaInfo('123');

      expect(result).toEqual({
        required: false,
        methods: [MfaMethods.EMAIL],
      });
      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: Buffer.from('123', 'hex'), isDeleted: false },
        select: ['isMfaRequired', 'totpSecret'],
      });
    });

    it('should return MFA info when user has MFA enabled and TOTP set', async () => {
      const mockUser = { isMfaRequired: true, totpSecret: 'secret' };

      (userRepository.findOne as jest.Mock).mockResolvedValue(mockUser);

      const result = await userService.getUserMfaInfo('123');

      expect(result).toEqual({
        required: true,
        methods: [MfaMethods.EMAIL, MfaMethods.TOTP],
      });
      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: Buffer.from('123', 'hex'), isDeleted: false },
        select: ['isMfaRequired', 'totpSecret'],
      });
    });
  });

  describe('changeMfaRequired', () => {
    it('should successfully change MFA required status', async () => {
      (userRepository.update as jest.Mock).mockResolvedValue({ affected: 1 });

      await expect(
        userService.changeMfaRequired('123', true),
      ).resolves.not.toThrow();

      expect(userRepository.update).toHaveBeenCalledWith(
        {
          id: Buffer.from('123', 'hex'),
          isMfaRequired: true,
          isDeleted: false,
        },
        { isMfaRequired: true },
      );
    });

    it('should throw an error if no rows were affected (MFA status not changed)', async () => {
      (userRepository.update as jest.Mock).mockResolvedValue({ affected: 0 });

      await expect(userService.changeMfaRequired('123', true)).rejects.toThrow(
        Errors.NOT_MODIFIED.message,
      );

      expect(userRepository.update).toHaveBeenCalledWith(
        {
          id: Buffer.from('123', 'hex'),
          isMfaRequired: true,
          isDeleted: false,
        },
        { isMfaRequired: true },
      );
    });
  });

  describe('disableTotpMfa', () => {
    it('should disable TOTP MFA by setting totpSecret to null', async () => {
      (userRepository.update as jest.Mock).mockResolvedValue({ affected: 1 });

      await expect(userService.disableTotpMfa('123')).resolves.not.toThrow();

      expect(userRepository.update).toHaveBeenCalledWith(
        { id: Buffer.from('123', 'hex'), isDeleted: false },
        { totpSecret: null },
      );
    });
  });

  describe('setTotpSecret', () => {
    it('should set the TOTP secret for a user', async () => {
      (userRepository.update as jest.Mock).mockResolvedValue({ affected: 1 });

      const totpSecret = 'someTotpSecret';

      await expect(
        userService.setTotpSecret('123', totpSecret),
      ).resolves.not.toThrow();

      expect(userRepository.update).toHaveBeenCalledWith(
        { id: Buffer.from('123', 'hex'), isDeleted: false },
        { totpSecret },
      );
    });
  });

  describe('getTotpSecret', () => {
    it('should throw an error if the user is not found', async () => {
      (userRepository.findOne as jest.Mock).mockResolvedValue(null);

      await expect(userService.getTotpSecret('123')).rejects.toThrow(
        Errors.USER_NOT_FOUND.message,
      );

      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: Buffer.from('123', 'hex'), isDeleted: false },
        select: ['totpSecret'],
      });
    });

    it('should return the TOTP secret if it exists', async () => {
      const mockUser = { totpSecret: 'secret123' };

      (userRepository.findOne as jest.Mock).mockResolvedValue(mockUser);

      const result = await userService.getTotpSecret('123');

      expect(result).toBe('secret123');
      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: Buffer.from('123', 'hex'), isDeleted: false },
        select: ['totpSecret'],
      });
    });

    it('should return null if the TOTP secret is not set', async () => {
      const mockUser = { totpSecret: null };

      (userRepository.findOne as jest.Mock).mockResolvedValue(mockUser);

      const result = await userService.getTotpSecret('123');

      expect(result).toBeNull();
      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: Buffer.from('123', 'hex'), isDeleted: false },
        select: ['totpSecret'],
      });
    });
  });
});
