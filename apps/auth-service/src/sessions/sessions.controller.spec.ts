import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';
import { JwtAuthGuard } from '../strategies/jwt-auth.guard';
import { SessionsController } from './sessions.controller';
import { SessionsService } from './sessions.service';

// Mock the JwtAuthGuard to bypass authentication and inject a fake user
class MockJwtAuthGuard {
  canActivate(context: any) {
    const req = context.switchToHttp().getRequest();
    req.user = {
      // Simulate the payload from a JWT token
      token: {
        sub: 'mock-user-id-123',
      },
    };
    return true;
  }
}

describe('SessionsController', () => {
  let app: INestApplication;
  let sessionsService: SessionsService;

  beforeAll(async () => {
    // Create a mock for the SessionsService
    const mockSessionsService = {
      findSessionsByUser: jest.fn(),
      revokeSession: jest.fn(),
      revokeAllUserSessions: jest.fn(),
    };

    const moduleRef: TestingModule = await Test.createTestingModule({
      controllers: [SessionsController],
      providers: [
        {
          provide: SessionsService,
          useValue: mockSessionsService,
        },
      ],
    })
      .overrideGuard(JwtAuthGuard)
      .useClass(MockJwtAuthGuard)
      .compile();

    app = moduleRef.createNestApplication();
    await app.init();

    // Get the mock service instance to spy on its methods
    sessionsService = moduleRef.get<SessionsService>(SessionsService);
  });

  afterAll(async () => {
    await app.close();
  });

  // Test for the GET /auth/sessions endpoint
  describe('GET /auth/sessions', () => {
    it('should return all sessions for the authenticated user', async () => {
      const mockSessions = [
        { id: 'session-id-1', userId: 'mock-user-id-123' },
        { id: 'session-id-2', userId: 'mock-user-id-123' },
      ];
      // Mock the service method to return our predefined sessions
      jest.spyOn(sessionsService, 'findSessionsByUser').mockResolvedValue(mockSessions as any);

      const response = await request(app.getHttpServer()).get('/auth/sessions').expect(200);

      // Assert that the response body matches our mock data
      expect(response.body).toEqual(mockSessions);
      // Assert that the service method was called with the correct user ID from the mock guard
      expect(sessionsService.findSessionsByUser).toHaveBeenCalledWith('mock-user-id-123');
    });
  });

  // Test for the DELETE /auth/sessions/:id endpoint
  describe('DELETE /auth/sessions/:id', () => {
    it('should successfully revoke a specific session', async () => {
      const sessionId = 'session-to-revoke-id';
      const mockRevokedSession = { id: sessionId, revoked: true };
      // Mock the service method to return a success object
      jest.spyOn(sessionsService, 'revokeSession').mockResolvedValue(mockRevokedSession as any);

      const response = await request(app.getHttpServer()).delete(`/auth/sessions/${sessionId}`).expect(200);

      expect(response.body).toEqual(mockRevokedSession);
      expect(sessionsService.revokeSession).toHaveBeenCalledWith(sessionId);
    });
  });

  // Test for the DELETE /auth/sessions endpoint
  describe('DELETE /auth/sessions', () => {
    it('should successfully revoke all sessions for the authenticated user', async () => {
      const userId = 'mock-user-id-123';
      const mockRevocationResult = { message: 'All sessions revoked', count: 2 };
      // Mock the service method to return a success object
      jest.spyOn(sessionsService, 'revokeAllUserSessions').mockResolvedValue(mockRevocationResult as any);

      const response = await request(app.getHttpServer()).delete('/auth/sessions').expect(200);

      expect(response.body).toEqual(mockRevocationResult);
      expect(sessionsService.revokeAllUserSessions).toHaveBeenCalledWith(userId);
    });
  });
});
