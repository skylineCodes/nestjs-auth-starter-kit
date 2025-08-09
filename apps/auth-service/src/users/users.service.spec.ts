import { Test, TestingModule } from '@nestjs/testing';
import { UsersService } from './users.service';
import { UsersRepository } from './repositories/users.repository';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { SessionsService } from '../sessions/sessions.service';
import { LoginActivityService } from '../login-activity/login-activity.service';
import { ForbiddenException, UnauthorizedException, UnprocessableEntityException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import * as useragent from 'useragent';
import { Request, Response } from 'express';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './models/user.schema';

// Mock the dependencies
const mockUsersRepository = () => ({
  create: jest.fn(),
  findOne: jest.fn(),
  findOneAndUpdate: jest.fn(),
  find: jest.fn(),
});

const mockConfigService = () => ({
  get: jest.fn((key: string) => {
    switch (key) {
      case 'JWT_ACCESS_EXPIRY':
        return '3600000'; // 1 hour
      case 'JWT_REFRESH_EXPIRY':
        return '604800000'; // 7 days
      default:
        return null;
    }
  }),
});

const mockJwtService = () => ({
  sign: jest.fn(() => 'vkcbla;vaehrvwerq'),
  verifyAsync: jest.fn(),
});

const mockSessionsService = () => ({
  findActiveSession: jest.fn(),
  createSession: jest.fn(),
  updateLastSeen: jest.fn(),
  updateSession: jest.fn(),
});

const mockLoginActivityService = () => ({
  logActivity: jest.fn(),
});

// Mock bcrypt and useragent
jest.mock('bcrypt');
jest.mock('useragent');

describe('UsersService', () => {
  let service: UsersService;
  let userRepo: jest.Mocked<UsersRepository>;
  let sessionsService: jest.Mocked<SessionsService>;
  let loginActivityService: jest.Mocked<LoginActivityService>;
  let configService: jest.Mocked<ConfigService>;
  let jwtService: jest.Mocked<JwtService>;

  beforeAll(() => {
    process.env.JWT_ACCESS_EXPIRY = '3600000'; // 1 hour in ms
    process.env.JWT_REFRESH_EXPIRY = '604800000'; // 7 days in ms
  });

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        { provide: UsersRepository, useFactory: mockUsersRepository },
        { provide: ConfigService, useFactory: mockConfigService },
        { provide: JwtService, useFactory: mockJwtService },
        { provide: SessionsService, useFactory: mockSessionsService },
        { provide: LoginActivityService, useFactory: mockLoginActivityService },
      ],
    }).compile();

    service = module.get<UsersService>(UsersService);
    userRepo = module.get(UsersRepository);
    sessionsService = module.get(SessionsService);
    loginActivityService = module.get(LoginActivityService);
    configService = module.get(ConfigService);
    jwtService = module.get(JwtService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('create', () => {
    const mockCreateUserDto: CreateUserDto = {
      firstName: 'John',
      lastName: 'Doe',
      email: 'john.doe@test.com',
      password: 'password123',
      phone: '',
      resetOtp: null,
      resetOtpExpires: null,
      otpRequestWindowStart: null,
      type: '',
      isEmailVerified: false,
      isActive: false,
      lastLoginAt: null
    };
    const mockResponse = {} as Response;

    it('should create a user successfully', async () => {
      // Mock the private validation method
      jest.spyOn<any, any>(service, 'validateCreateUserDto').mockResolvedValue(undefined);
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashedPassword');
      userRepo.create.mockResolvedValue({} as any);

      const result = await service.create(mockCreateUserDto, mockResponse);

      expect(result).toEqual({
        status: 200,
        message: 'Account created successfully!',
      });
      expect(bcrypt.hash).toHaveBeenCalledWith('password123', 10);
      expect(userRepo.create).toHaveBeenCalledWith({
        ...mockCreateUserDto,
        passwordHash: 'hashedPassword',
      });
    });

    it('should handle duplicate key error (11000)', async () => {
      const mockError = { code: '11000', message: 'Duplicate key error' };
      jest.spyOn<any, any>(service, 'validateCreateUserDto').mockRejectedValue(mockError);

      const result = await service.create(mockCreateUserDto, mockResponse);

      expect(result).toEqual({ status: 500, message: 'Duplicate key error' });
    });

    it('should throw UnprocessableEntityException from validation', async () => {
      const mockError = new UnprocessableEntityException('Email already exists.');
      jest.spyOn<any, any>(service, 'validateCreateUserDto').mockRejectedValue(mockError);

      await expect(service.create(mockCreateUserDto, mockResponse)).rejects.toThrow(UnprocessableEntityException);
    });

    it('should handle a generic error', async () => {
      const mockError = new Error('Some generic error');
      jest.spyOn<any, any>(service, 'validateCreateUserDto').mockRejectedValue(mockError);

      const result = await service.create(mockCreateUserDto, mockResponse);

      expect(result).toEqual({ status: 500, message: 'Some generic error' });
    });
  });

  describe('getUserByEmail', () => {
    it('should find a user by email', async () => {
      const mockUser = { email: 'test@email.com' };
      userRepo.findOne.mockResolvedValue(mockUser as any);

      const result = await service.getUserByEmail('test@email.com');

      expect(userRepo.findOne).toHaveBeenCalledWith({ email: 'test@email.com' });
      expect(result).toEqual({ status: 200, data: mockUser });
    });

    it('should handle errors', async () => {
      const mockError = new Error('DB error');
      userRepo.findOne.mockRejectedValue(mockError);

      const result = await service.getUserByEmail('test@email.com');

      expect(result).toEqual({ status: 500, message: 'DB error' });
    });
  });

  describe('getUserByOtp', () => {
    it('should find a user by otp', async () => {
      const mockUser = { resetOtp: '123456' };
      userRepo.findOne.mockResolvedValue(mockUser as any);

      const result = await service.getUserByOtp('123456');

      expect(userRepo.findOne).toHaveBeenCalledWith({ resetOtp: '123456' });
      expect(result).toEqual({ status: 200, data: mockUser });
    });
  });

  describe('getUserByPhone', () => {
    it('should find a user by phone', async () => {
      const mockUser = { phone: '1234567890' };
      userRepo.findOne.mockResolvedValue(mockUser as any);

      const result = await service.getUserByPhone('1234567890');

      expect(userRepo.findOne).toHaveBeenCalledWith({ phone: '1234567890' });
      expect(result).toEqual({ status: 200, data: mockUser });
    });
  });

  describe('getUserById', () => {
    it('should find a user by id', async () => {
      const mockUser = { _id: 'user-id-1' };
      userRepo.findOne.mockResolvedValue(mockUser as any);

      const result = await service.getUserById('user-id-1');

      expect(userRepo.findOne).toHaveBeenCalledWith({ _id: 'user-id-1' });
      expect(result).toEqual({ status: 200, data: mockUser });
    });
  });

  describe('checkIfUserExists', () => {
    it('should return true if user exists', async () => {
      jest.spyOn(service, 'getUserByEmail').mockResolvedValue({ status: 200, data: {} } as any);
      const result = await service.checkIfUserExists('test@email.com');
      expect(result).toEqual({ status: 200, data: true });
    });

    it('should return false if user does not exist', async () => {
      jest.spyOn(service, 'getUserByEmail').mockResolvedValue({ status: 200, data: null } as any);
      const result = await service.checkIfUserExists('test@email.com');
      expect(result).toEqual({ status: 200, data: false });
    });
  });

  describe('setPasswordResetOtp', () => {
    const userId = 'user-id-1';
    const otp = '123456';
    const now = new Date();

    it('should set OTP for the first time', async () => {
      const mockUser = { data: { otpRequestCount: 0, otpRequestWindowStart: null } };
      jest.spyOn(service, 'getUserById').mockResolvedValue(mockUser as any);
      userRepo.findOneAndUpdate.mockResolvedValue({} as any);

      await service.setPasswordResetOtp(userId, otp);

      expect(userRepo.findOneAndUpdate).toHaveBeenCalledWith(
        { _id: userId },
        expect.objectContaining({
          resetOtp: otp,
          resetOtpExpires: expect.any(Date),
          otpRequestCount: 1,
          otpRequestWindowStart: expect.any(Date),
        }),
      );
    });

    it('should increment OTP count within the window', async () => {
      const oneMinuteAgo = new Date(now.getTime() - 60000);
      const mockUser = { data: { otpRequestCount: 1, otpRequestWindowStart: oneMinuteAgo } };
      jest.spyOn(service, 'getUserById').mockResolvedValue(mockUser as any);
      userRepo.findOneAndUpdate.mockResolvedValue({} as any);

      await service.setPasswordResetOtp(userId, otp);

      expect(userRepo.findOneAndUpdate).toHaveBeenCalledWith(
        { _id: userId },
        expect.objectContaining({
          resetOtp: otp,
          resetOtpExpires: expect.any(Date),
          $inc: { otpRequestCount: 1 },
        }),
      );
    });

    it('should throw ForbiddenException for too many attempts', async () => {
      const fiveMinutesAgo = new Date(now.getTime() - 5 * 60000);
      const mockUser = { data: { otpRequestCount: 5, otpRequestWindowStart: fiveMinutesAgo } };
      jest.spyOn(service, 'getUserById').mockResolvedValue(mockUser as any);

      await expect(service.setPasswordResetOtp(userId, otp)).rejects.toThrow(ForbiddenException);
    });
  });

  describe('validateUserCredentialsByEmail', () => {
    const email = 'test@email.com';
    const password = 'password123';
    const mockRequest = { ip: '127.0.0.1', get: jest.fn().mockReturnValue('mock-agent') } as unknown as Request;
    const mockUser = { _id: 'user-id-1', passwordHash: 'hashedPassword' } as any;

    it('should validate user credentials successfully', async () => {
      jest.spyOn(service, 'getUserByEmail').mockResolvedValue({ status: 200, data: mockUser });
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);

      const result = await service.validateUserCredentialsByEmail(email, password, mockRequest);

      expect(result).toEqual({ status: 200, data: mockUser });
      expect(bcrypt.compare).toHaveBeenCalledWith(password, 'hashedPassword');
    });

    it('should return a 500 error object if user not found', async () => {
      jest.spyOn(service, 'getUserByEmail').mockResolvedValue({ status: 200, data: null });

      const result = await service.validateUserCredentialsByEmail(email, password, mockRequest);
      expect(result).toEqual({ status: 500, message: 'User not found' });
    });

    it('should return a 500 error object if password invalid and log activity', async () => {
      jest.spyOn(service, 'getUserByEmail').mockResolvedValue({ status: 200, data: mockUser });
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      const result = await service.validateUserCredentialsByEmail(email, password, mockRequest);

      expect(result).toEqual({ status: 500, message: 'Invalid credentials' });
      expect(loginActivityService.logActivity).toHaveBeenCalledWith({
        userId: 'user-id-1',
        status: 'failed',
        ipAddress: '127.0.0.1',
        userAgent: 'mock-agent',
        reason: 'Invalid credentials',
      });
    });
  });
  
  describe('validateUserCredentialsByPhone', () => {
    const phone = '1234567890';
    const password = 'password123';
    const mockUser = { _id: 'user-id-1', passwordHash: 'hashedPassword' } as any;

    it('should validate user credentials successfully', async () => {
      jest.spyOn(service, 'getUserByPhone').mockResolvedValue({ status: 200, data: mockUser });
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);

      const result = await service.validateUserCredentialsByPhone(phone, password);

      expect(result).toEqual({ status: 200, data: mockUser });
      expect(bcrypt.compare).toHaveBeenCalledWith(password, 'hashedPassword');
    });

    it('should throw UnauthorizedException if user not found', async () => {
      jest.spyOn(service, 'getUserByPhone').mockResolvedValue({ status: 200, data: null });

      await expect(service.validateUserCredentialsByPhone(phone, password)).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException if password invalid', async () => {
      jest.spyOn(service, 'getUserByPhone').mockResolvedValue({ status: 200, data: mockUser });
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      await expect(service.validateUserCredentialsByPhone(phone, password)).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('updateLastLogin', () => {
    it('should update last login timestamp', async () => {
      const userId = 'user-id-1';
      userRepo.findOneAndUpdate.mockResolvedValue({} as any);

      const result = await service.updateLastLogin(userId);

      expect(userRepo.findOneAndUpdate).toHaveBeenCalledWith(
        { _id: userId },
        { lastLoginAt: expect.any(Date) },
      );
      expect(result).toEqual({ status: 200, message: 'Update successful!' });
    });
  });

  describe('updateUserProfile', () => {
    it('should update user profile', async () => {
      const userId = 'user-id-1';
      const mockUpdateDto: UpdateUserDto = { firstName: 'Jane' };
      userRepo.findOneAndUpdate.mockResolvedValue({} as any);

      const result = await service.updateUserProfile(userId, mockUpdateDto);

      expect(userRepo.findOneAndUpdate).toHaveBeenCalledWith(
        { _id: userId },
        mockUpdateDto,
      );
      expect(result).toEqual({ status: 200, message: 'Update successful!' });
    });
  });

  describe('deactivateUser', () => {
    it('should deactivate a user', async () => {
      const userId = 'user-id-1';
      userRepo.findOneAndUpdate.mockResolvedValue({} as any);

      const result = await service.deactivateUser(userId);

      expect(userRepo.findOneAndUpdate).toHaveBeenCalledWith(
        { _id: userId },
        { isActive: false },
      );
      expect(result).toEqual({ status: 200, message: 'Update successful!' });
    });
  });

  describe('getAllUsers', () => {
    it('should return all users', async () => {
      const mockUsers = [{ _id: 'u1' }, { _id: 'u2' }];
      userRepo.find.mockResolvedValue(mockUsers as any);

      const result = await service.getAllUsers();

      expect(userRepo.find).toHaveBeenCalled();
      expect(result).toEqual({ status: 200, data: mockUsers });
    });
  });

  describe('setAuthToken', () => {
    const mockResponse = { cookie: jest.fn() } as unknown as Response;
    const mockUser = { _id: 'user-id-1', type: 'user' } as unknown as User;
    const mockSession = { _id: 'session-id-1' };
    const expiry = 3600000;

    it('should set an authentication cookie', async () => {
      configService.get.mockReturnValueOnce(expiry).mockReturnValueOnce('JWT_ACCESS_SECRET');
      (service as any).generateAccessToken = jest.fn().mockReturnValue('ovlwesbw[wpove');

      await service.setAuthToken(mockUser, mockSession, mockResponse);

      expect(mockResponse.cookie).toHaveBeenCalledWith('Authentication', 'ovlwesbw[wpove', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: expiry,
      });
      expect((service as any).generateAccessToken).toHaveBeenCalledWith('user-id-1', 'user', 'session-id-1');
    });

    it('should throw an error for invalid expiry', async () => {
      configService.get
        .mockReturnValueOnce('invalid-expiry')
        .mockReturnValueOnce('JWT_ACCESS_SECRET');

      await expect(service.setAuthToken(mockUser, mockSession, mockResponse))
      .resolves.not.toThrow();
    });
  });

  describe('setSessionToken', () => {
    const mockUser = { _id: 'user-id-1' } as any;
    const mockRequest = { ip: '127.0.0.1', headers: { 'user-agent': 'mock-agent' } } as Request;
    const mockResponse = { cookie: jest.fn() } as unknown as Response;

    it('should create and set a new session token', async () => {
      sessionsService.findActiveSession.mockResolvedValue({ status: 200, data: null });
      sessionsService.createSession.mockResolvedValue({ status: 200, data: { _id: 'new-session-id' } } as any);
      (useragent.parse as jest.Mock).mockReturnValue({ toString: () => 'mock-agent' });
      (service as any).generateAccessToken = jest.fn().mockReturnValue('mock-access-token');

      // Add mocks for the configService to prevent the authentication token from failing
      configService.get.mockImplementation((key: string) => {
        if (key === 'JWT_ACCESS_EXPIRY') return '3600';
        if (key === 'JWT_REFRESH_EXPIRY') return '1200';
        if (key === 'JWT_ACCESS_SECRET') return 'ACCESS_SECRET';
        if (key === 'JWT_REFRESH_SECRET') return 'REFRESH_SECRET';
        return key;
      });

      const result = await service.setSessionToken(mockUser, mockRequest, mockResponse);

      expect(sessionsService.findActiveSession).toHaveBeenCalled();
      expect(sessionsService.createSession).toHaveBeenCalled();
      expect(mockResponse.cookie).toHaveBeenCalledWith('SessionId', 'new-session-id', expect.any(Object));
      expect(result).toEqual({ data: 'new-session-id' });
    });

    it('should use and set an existing session token', async () => {
      sessionsService.findActiveSession.mockResolvedValue({ status: 200, data: { _id: 'existing-session-id' } } as any);

      const result = await service.setSessionToken(mockUser, mockRequest, mockResponse);

      expect(sessionsService.findActiveSession).toHaveBeenCalled();
      expect(sessionsService.createSession).not.toHaveBeenCalled();
      expect(mockResponse.cookie).toHaveBeenCalledWith('SessionId', 'existing-session-id', expect.any(Object));
      expect(result).toEqual({ data: 'existing-session-id' });
    });
  });

  describe('setRefreshToken', () => {
    const mockUser = { _id: 'user-id-1' } as any;
    const sessionId = 'session-id-13454'
    const mockResponse = () => {
      const res: any = {};
      res.cookie = jest.fn().mockReturnValue(res);
      return res;
    };

    const res = mockResponse();

    it('should set a refresh token cookie', async () => {
      const mockUser = { _id: 'user-id-1' } as any;
      const sessionId = { _id: 'session-id-1' };
      const res = {
        cookie: jest.fn().mockReturnThis(),
      } as unknown as Response;

      (service as any).generateRefreshToken = jest.fn().mockReturnValue('mock-refresh-token');

      configService.get
        .mockReturnValueOnce('120000') // expiry in ms
        .mockReturnValueOnce('JWT_REFRESH_SECRET');

      await service.setRefreshToken(mockUser, sessionId, res);

      expect(res.cookie).toHaveBeenCalledWith('refreshToken', 'mock-refresh-token', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 120000,
      });
      
      expect((service as any).generateRefreshToken)
      .toHaveBeenCalledWith('user-id-1', undefined, 'session-id-1');
    });

    it('should throw an error for invalid expiry', async () => {
      const mockResponse = {
        cookie: jest.fn().mockReturnThis(),
        clearCookie: jest.fn().mockReturnThis(),
      } as unknown as Response;

      configService.get.mockReturnValue('invalid-expiry');
      await expect(service.setRefreshToken(mockUser, sessionId, mockResponse)).rejects.toThrow('Failed to set authentication token');
    });
  });

  describe('verifyRefreshToken', () => {
    it('should verify a token successfully', async () => {
      const payload = { sub: 'user-id-1' };
      jwtService.verifyAsync.mockResolvedValue(payload as any);
      configService.get.mockReturnValue('JWT_REFRESH_SECRET');

      const result = await service.verifyRefreshToken('mock-token');

      expect(jwtService.verifyAsync).toHaveBeenCalled();
      expect(result).toEqual(payload);
    });

    it('should throw an error for an invalid token', async () => {
      jwtService.verifyAsync.mockRejectedValue(new Error('Invalid token'));

      await expect(service.verifyRefreshToken('invalid-token')).rejects.toThrow('Invalid token');
    });
  });

  describe('Private Methods', () => {
    it('generateAccessToken should call jwtService.sign with correct payload and options', () => {
      configService.get.mockReturnValueOnce('3600').mockReturnValueOnce('ACCESS_SECRET');
      jwtService.sign.mockReturnValue('mock-token');

      (service as any).generateAccessToken('user-id-1', 'user', 'session-id-1');

      expect(jwtService.sign).toHaveBeenCalledWith(
        { sub: 'user-id-1', type: 'user', sessionId: 'session-id-1' },
        { secret: 'ACCESS_SECRET', expiresIn: 3600 },
      );
    });

    it('generateRefreshToken should call jwtService.sign with correct payload and options', () => {
      configService.get.mockReturnValueOnce('1200').mockReturnValueOnce('REFRESH_SECRET');
      jwtService.sign.mockReturnValue('mock-token');

      (service as any).generateRefreshToken('user-id-1');

      expect(jwtService.sign).toHaveBeenCalledWith(
        { sub: 'user-id-1' },
        { secret: 'REFRESH_SECRET', expiresIn: 1200 },
      );
    });

    it('generateResetToken should call jwtService.sign with correct payload and options', () => {
      configService.get.mockReturnValueOnce('900').mockReturnValueOnce('RESET_SECRET');
      jwtService.sign.mockReturnValue('mock-token');

      service.generateResetToken('user-id-1');

      expect(jwtService.sign).toHaveBeenCalledWith(
        { sub: 'user-id-1' },
        { secret: 'RESET_SECRET', expiresIn: 900 },
      );
    });

    it('validateCreateUserDto should throw UnprocessableEntityException if user exists', async () => {
      userRepo.findOne.mockResolvedValue({} as any);

      await expect((service as any).validateCreateUserDto({ email: 'test@email.com' })).rejects.toThrow(UnprocessableEntityException);
    });

    it('validateCreateUserDto should not throw if user does not exist', async () => {
      userRepo.findOne.mockResolvedValue(null);

      await expect((service as any).validateCreateUserDto({ email: 'test@email.com' })).resolves.toBeUndefined();
    });
  });
});
