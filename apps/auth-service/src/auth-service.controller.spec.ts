import * as request from 'supertest';
import { Test, TestingModule } from '@nestjs/testing';
import { AuthServiceService } from './auth-service.service';
import { AuthServiceController } from './auth-service.controller';
import { LoginActivityService } from './login-activity/login-activity.service';
import { CanActivate, ExecutionContext, INestApplication, Injectable } from '@nestjs/common';
import { JwtAuthGuard } from './strategies/jwt-auth.guard';

@Injectable()
export class MockJwtAuthGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();

    request.user = {
      _id: 'user-id-from-mock',
      email: 'test@mail.com',
    };

    return true;
  }
}

describe('AuthServiceController', () => {
  let app: INestApplication;
  let mockAuthService: Partial<AuthServiceService>;
  // let mockLoginActivityService: Partial<LoginActivityService>;

  beforeAll(async () => {
    mockAuthService = {
      register: jest.fn().mockResolvedValue({ status: 201, data: { userId: '123' } }),
      login: jest.fn().mockResolvedValue({ status: 200, data: { accessToken: 'abc' } }),
      refreshToken: jest.fn().mockResolvedValue({ status: 200, data: { accessToken: 'xyz' } }),
      logout: jest.fn().mockResolvedValue({ status: 200, data: {} }),
      forgotPassword: jest.fn().mockResolvedValue({ status: 200, message: 'OTP sent' }),
      resetPassword: jest.fn().mockResolvedValue({ status: 200, message: 'Password reset' }),
      resendResetOtp: jest.fn().mockResolvedValue({ status: 200, message: 'OTP resent' }),
    };

    let mockLoginActivityService = {
      getLogsForUser: jest.fn().mockResolvedValue({
        status: 200,
        data: {
          _id: '688f7d698290ba6e120d0ce0',
          createdAt: '2025-08-03T15:16:57.979Z',
          ipAddress: '::ffff:172.19.0.8',
          status: 'success',
          updatedAt: '2025-08-03T15:16:57.979Z',
          userAgent: 'PostmanRuntime/7.44.0',
          userId: '688f7d648290ba6e120d0cda',
        },
      }),
    };

    const moduleRef: TestingModule = await Test.createTestingModule({
      controllers: [AuthServiceController],
      providers: [
        { provide: AuthServiceService, useValue: mockAuthService },
        { provide: LoginActivityService, useValue: mockLoginActivityService },
      ],
    })
    .overrideGuard(JwtAuthGuard)
    .useValue(new MockJwtAuthGuard())
    .compile();

    app = moduleRef.createNestApplication();

    // ✅ Move this after app is initialized
    app.useGlobalGuards({
      canActivate: (context: ExecutionContext) => {
        const request = context.switchToHttp().getRequest();
        request.user = { userId: '123' }; // mock user
        return true;
      },
    } as any);

    await app.init();
  });

  it('/register (POST)', () => {
    return request(app.getHttpServer())
      .post('/auth/register')
      .send({ email: 'test@mail.com', password: 'Pass1234!', firstName: 'Test', lastName: 'User' })
      .expect(201)
      .expect(res => {
        expect(res.body.data.userId).toBe('123');
      });
  });

  it('/login (POST)', () => {
    return request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: 'test@mail.com', password: 'Pass1234!' })
      .expect(200)
      .expect(res => {
        expect(res.body.data.accessToken).toBe('abc');
      });
  });

  it('/refresh (POST)', () => {
    return request(app.getHttpServer())
      .post('/auth/refresh')
      .set('Cookie', ['refreshToken=my-refresh-token'])
      .expect(200)
      .expect(res => {
        expect(res.body.data.accessToken).toBe('xyz');
      });
  });

  it('/logout (POST)', () => {
    return request(app.getHttpServer())
      .post('/auth/logout')
      .set('Cookie', ['refreshToken=eyJh1NiIsInR5cCI6IkpXVCJ9', 'Authentication=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', 'SessionId=eyJhbGciOiJIUzI1NnR5cCI6IkpX'])
      .set('x-session-id', '688f7d6a8290ba6e120d0ce4')
      .set('x-logout-all', 'true')
      .then(res => {
        console.log(res.status, res.body);
        expect(res.status).toBe(200);
      });
  });

  it('/forgot-password (POST)', () => {
    return request(app.getHttpServer())
      .post('/auth/forgot-password')
      .send({ email: 'test@mail.com' })
      .expect(200)
      .expect(res => {
        expect(res.body.message).toBe('OTP sent');
      });
  });

  it('/reset-password (POST)', () => {
    return request(app.getHttpServer())
      .post('/auth/reset-password')
      .send({ email: 'test@mail.com', otp: '123456', newPassword: 'NewPass123!' })
      .expect(200)
      .expect(res => {
        expect(res.body.message).toBe('Password reset');
      });
  });

  it('/resend-reset-password (POST)', () => {
    return request(app.getHttpServer())
      .post('/auth/resend-reset-password')
      .send({ email: 'test@mail.com' })
      .expect(200)
      .expect(res => {
        expect(res.body.message).toBe('OTP resent');
      });
  });

  it('/me (GET)', () => {
    return request(app.getHttpServer())
      .get('/auth/me')
      .expect(200)
      .expect(res => {
        expect(res.body.data).toEqual({
          _id: 'user-id-from-mock',
          email: 'test@mail.com',
        });
      });
  });

  // Corrected test case for /audit-logs/:userId
  it('/audit-logs/:userId (GET)', async () => {
    const userId = '688f7d648290ba6e120d0cda';
    const mockLoginActivity = {
      _id: '688f7d698290ba6e120d0ce0',
      createdAt: '2025-08-03T15:16:57.979Z',
      ipAddress: '::ffff:172.19.0.8',
      status: 'success',
      updatedAt: '2025-08-03T15:16:57.979Z',
      userAgent: 'PostmanRuntime/7.44.0',
      userId: '688f7d648290ba6e120d0cda',
    };
    
    return request(app.getHttpServer())
      .get(`/auth/audit-logs/${userId}`)
      .expect(200)
      .expect(res => {
        expect(res.body.data).toEqual(mockLoginActivity);
        expect(res.body.status).toEqual(200);
      });
  });

  afterAll(async () => {
    await app.close();
  });
});
