import { Test, TestingModule } from '@nestjs/testing';
import { AuthServiceService } from './auth-service.service';
import { UsersService } from './users/users.service';
import { SessionsService } from './sessions/sessions.service';
import { LoginActivityService } from './login-activity/login-activity.service';
import { BadRequestException, ConflictException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { Response, Request } from 'express';
import { mock } from 'jest-mock-extended';
import { RegisterDto } from './dto/register.dto';

const mockUsersService = {
  create: jest.fn(),
  validateUserCredentialsByEmail: jest.fn(),
  updateLastLogin: jest.fn(),
  setSessionToken: jest.fn(),
  setAuthToken: jest.fn(),
  setRefreshToken: jest.fn(),
  verifyRefreshToken: jest.fn(),
  getUserByEmail: jest.fn(),
  setPasswordResetOtp: jest.fn(),
  getUserByOtp: jest.fn(),
  updateUserProfile: jest.fn(),
};

const mockSessionsService = {
  revokeSession: jest.fn(),
  getById: jest.fn().mockResolvedValue({
    status: 200,
    data: { _id: 'sess-123', userId: 'user123' }
  }),
  revokeAllUserSessions: jest.fn(),
};

const mockLoginActivityService = {
  detectAnomaly: jest.fn(),
  logActivity: jest.fn(),
};

const mockNotificationsService = {
  emit: jest.fn(),
};

function createValidUserDto(): RegisterDto {
  return {
    firstName: 'Test',
    lastName: 'User',
    email: 'user@test.com',
    password: 'StrongP@ssw0rd!',
    phone: '08012345678',
    type: 'member',
    isEmailVerified: false,
    isActive: true,
    resetOtp: null,
    resetOtpExpires: null,
    otpRequestWindowStart: null,
    lastLoginAt: null,
  };
}

// function mockRequest(cookies: Record<string, any> = {}): Request {
//   return { cookies } as unknown as Request;
// }

function mockRequest(data: Partial<Request>): Partial<Request> {
  return {
    cookies: {},
    user: {},
    ...data,
  } as Partial<Request> & { refreshToken?: string };
}

describe('AuthServiceService', () => {
  let service: AuthServiceService;

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthServiceService,
        { provide: UsersService, useValue: mockUsersService },
        { provide: SessionsService, useValue: mockSessionsService },
        { provide: LoginActivityService, useValue: mockLoginActivityService },
        { provide: 'notification-service-auth-kit', useValue: mockNotificationsService },
      ],
    }).compile();

    service = module.get<AuthServiceService>(AuthServiceService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('register', () => {
    it('should register user successfully', async () => {
      mockUsersService.create.mockResolvedValue({});
      const response = {} as Response;
      const dto = createValidUserDto();

      const result = await service.register(dto, response);
      expect(result.status).toBe(200);
    });

    it('should throw conflict or bad request exception', async () => {
      // mockUsersService.create.mockImplementation(() => {
      //   throw new ConflictException('User exists');
      // });

      mockUsersService.create.mockImplementationOnce(() => {
        throw new ConflictException('User exists');
      });

      const dto = {
        firstName: 'Jane',
        lastName: 'Doe',
        email: 'jane@test.com',
        password: 'StrongP@ssw0rd!',
        phone: '08012345678',
        type: 'member',
        isEmailVerified: false,
        isActive: true,
        resetOtp: null,
        resetOtpExpires: null,
        otpRequestWindowStart: null,
        lastLoginAt: null,
      };

      await expect(service.register(dto, {} as Response)).rejects.toThrow(ConflictException);
    });
  });

  describe('login', () => {
    it('should log in user successfully', async () => {
      const req = {
        ip: '127.0.0.1',
        get: jest.fn().mockReturnValue('MockUserAgent'),
      } as unknown as Request;

      const res = {} as Response;

      const mockUser = { _id: 'user123', email: 'test@example.com' };

      mockUsersService.validateUserCredentialsByEmail.mockResolvedValue({
        status: 200,
        data: mockUser,
      });

      mockLoginActivityService.detectAnomaly.mockResolvedValue({
        location: 'Lagos',
        isNewLocation: false,
      });

      mockLoginActivityService.logActivity.mockResolvedValue(undefined);

      mockUsersService.updateLastLogin.mockResolvedValue(undefined);
      mockUsersService.setSessionToken.mockResolvedValue({ data: 'session-id' });
      mockUsersService.setAuthToken.mockResolvedValue(undefined);
      mockUsersService.setRefreshToken.mockResolvedValue(undefined);

      const result = await service.login({ email: 'test@example.com', password: 'password' }, req, res);

      expect(result.status).toBe(200);
      expect(result.message).toBe('User logged in successfully!');
    });

    it('should return error if login fails', async () => {
      const req = {} as unknown as Request;
      const res = {} as Response;

      mockUsersService.validateUserCredentialsByEmail.mockResolvedValue({
        status: 401,
        message: 'Invalid credentials',
        data: null,
      });

      const result = await service.login({ email: 'wrong@example.com', password: 'wrong' }, req, res);

      expect(result.status).toBe(500);
      expect(result.message).toBe('Invalid credentials');
    });
  });

  describe('logout', () => {
    const res = {
      clearCookie: jest.fn(),
    } as unknown as Response;

    it('should revoke other device session', async () => {
      const req = { cookies: {} } as Request;
      await service.logout({
        sessionId: 'abc123',
        logoutAll: false
      }, req, res);

      expect(mockSessionsService.revokeSession).toHaveBeenCalledWith('abc123');
    });

    it('should revoke current session and clear cookies', async () => {
      const res = { clearCookie: jest.fn() } as unknown as Response; // reset mock for each test

      const req = mockRequest({ cookies: { SessionId: 'current-session' } });

      const dto = {
        sessionId: null,
        logoutAll: false
      }

      const result = await service.logout(dto, req, res);

      expect(mockSessionsService.revokeSession).toHaveBeenCalledWith('current-session');
      expect(res.clearCookie).toHaveBeenCalledWith('Authentication', expect.any(Object));
      expect(res.clearCookie).toHaveBeenCalledWith('refreshToken', expect.any(Object));
      expect(res.clearCookie).toHaveBeenCalledWith('SessionId', expect.any(Object));
      expect(result?.status).toBe(200);
      expect(result?.message).toBe('Logged out successfully');
    });

    it('should revoke all sessions and clear cookies', async () => {
      const res = { clearCookie: jest.fn() } as unknown as Response;

      const req = mockRequest({
        cookies: { SessionId: 'current-session' },
        user: { _id: 'user123' },
      }) as Request;

      const dto = { logoutAll: true };

      const result = await service.logout(dto, req, res);

      expect(mockSessionsService.revokeAllUserSessions).toHaveBeenCalledWith('user123');
      expect(res.clearCookie).toHaveBeenCalledWith('Authentication', expect.any(Object));
      expect(res.clearCookie).toHaveBeenCalledWith('refreshToken', expect.any(Object));
      expect(res.clearCookie).toHaveBeenCalledWith('SessionId', expect.any(Object));
      expect(result?.message).toBe('Logged out all sessions successfully');
    });
  });

  describe('forgotPassword', () => {
    it('should send OTP if user exists', async () => {
      mockUsersService.getUserByEmail.mockResolvedValue({ data: { _id: '1' } });
      mockUsersService.setPasswordResetOtp.mockResolvedValue(true);

      const result = await service.forgotPassword({ email: 'test@test.com' });
      expect(result.status).toBe(200);
      expect(mockNotificationsService.emit).toHaveBeenCalled();
    });

    it('should throw NotFoundException if user does not exist', async () => {
      mockUsersService.getUserByEmail.mockResolvedValue(null);
      await expect(service.forgotPassword({ email: 'none@test.com' })).rejects.toThrow(NotFoundException);
    });
  });

  describe('resendResetOtp', () => {
    it('should resend OTP if valid user', async () => {
      mockUsersService.getUserByEmail.mockResolvedValue({ data: { _id: '1', resetOtpExpires: Date.now() + 60000 } });
      const result = await service.resendResetOtp({ email: 'test@test.com' });
      expect(result.status).toBe(200);
      expect(mockNotificationsService.emit).toHaveBeenCalled();
    });
  });

  describe('resetPassword', () => {
    const otp = '123456';
    const newPassword = 'NewStrongPassword';

    const mockUserData = {
      _id: 'user-id',
      email: 'test@example.com',
      resetOtp: otp,
      resetOtpExpires: new Date(Date.now() + 10000).toISOString(),
    };

    it('should reset password successfully', async () => {
      mockUsersService.getUserByOtp.mockResolvedValue({ data: mockUserData });
      mockUsersService.updateUserProfile.mockResolvedValue(undefined);
      const spy = jest.spyOn(service['notificationsService'], 'emit');

      const result = await service.resetPassword({ otp, newPassword });

      expect(mockUsersService.updateUserProfile).toHaveBeenCalledWith('user-id', expect.any(Object));
      expect(spy).toHaveBeenCalledWith(
        'notify_email',
        expect.objectContaining({ email: 'test@example.com' }),
      );
      expect(result.status).toBe(200);
      expect(result.message).toBe('Password reset successful');
    });

    it('should throw if user not found or OTP missing', async () => {
      mockUsersService.getUserByOtp.mockResolvedValue(null);
      await expect(service.resetPassword({ otp, newPassword })).rejects.toThrow(UnauthorizedException);
    });

    it('should throw if OTP expired', async () => {
      mockUsersService.getUserByOtp.mockResolvedValue({
        data: {
          ...mockUserData,
          resetOtpExpires: new Date(Date.now() - 10000).toISOString(), // expired
        },
      });

      await expect(service.resetPassword({ otp, newPassword })).rejects.toThrow(UnauthorizedException);
    });

    it('should throw if OTP does not match', async () => {
      mockUsersService.getUserByOtp.mockResolvedValue({
        data: {
          ...mockUserData,
          resetOtp: 'wrongOtp',
        },
      });

      await expect(service.resetPassword({ otp, newPassword })).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('refreshToken', () => {
    it('should refresh token if valid', async () => {
      const req = mock<Request>();
      const sessionId = "session-2345"
      req.cookies = { refreshToken: 'my-token' };
      req.user = { _id: 'user123' } as any;

      const res = {} as Response;

      mockUsersService.verifyRefreshToken.mockResolvedValue({ sub: '1', sessionId, type: 'user' });
      mockUsersService.setSessionToken.mockResolvedValue({ data: 'session-data' });

      const result = await service.refreshToken(req, res);
      expect(result.status).toBe(200);
    });

    it('should throw UnauthorizedException if no token', async () => {
      const req = { cookies: {} } as Request;
      await expect(service.refreshToken(req, {} as Response)).rejects.toThrow(UnauthorizedException);
    });
  });
});
