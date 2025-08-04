import { Test, TestingModule } from '@nestjs/testing';
import { SessionsService } from './sessions.service';
import { SessionRepository } from './repositories/session.repository';
import { UnprocessableEntityException } from '@nestjs/common';
import { CreateSessionDto } from './dto/create-session.dto';
import { UpdateSessionDto } from './dto/update-session.dto';
import { Response } from 'express';

// Mock the SessionRepository
const mockSessionRepository = () => ({
  create: jest.fn(),
  find: jest.fn(),
  findOne: jest.fn(),
  findOneAndUpdate: jest.fn(),
  updateMany: jest.fn(),
});

describe('SessionsService', () => {
  let service: SessionsService;
  let sessionRepository: jest.Mocked<SessionRepository>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SessionsService,
        {
          provide: SessionRepository,
          useFactory: mockSessionRepository,
        },
      ],
    }).compile();

    service = module.get<SessionsService>(SessionsService);
    sessionRepository = module.get(SessionRepository);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('createSession', () => {
    it('should create a session successfully', async () => {
      // CORRECTED: Assuming your DTO should contain all the necessary properties,
      // we create a mock object that matches what your service needs.
      const mockCreateDto = {
        userId: 'user-id-1',
        token: 'mock-token',
        userAgent: 'test-agent',
        ip: '127.0.0.1',
        revoked: false,
      };
      const mockSession = {
        _id: 'session-id-1',
        ...mockCreateDto,
        lastSeenAt: new Date(),
      };
      const mockResponse = {} as Response;

      sessionRepository.create.mockResolvedValue(mockSession as any);

      const result = await service.createSession(mockCreateDto as CreateSessionDto, mockResponse);

      expect(sessionRepository.create).toHaveBeenCalledWith(expect.objectContaining({
        ...mockCreateDto,
        lastSeenAt: expect.any(Date),
      }));
      expect(result).toEqual({
        status: 200,
        message: 'Session created successfully!',
        data: mockSession,
      });
    });

    it('should handle duplicate key error (11000)', async () => {
      const mockCreateDto: CreateSessionDto = { userId: 'user-id-1' };
      const mockResponse = {} as Response;
      const mockError = { code: '11000', message: 'Duplicate key error' };

      sessionRepository.create.mockRejectedValue(mockError);

      const result = await service.createSession(mockCreateDto, mockResponse);

      expect(result).toEqual({ status: 500, message: 'Duplicate key error' });
    });

    it('should throw UnprocessableEntityException', async () => {
      const mockCreateDto: CreateSessionDto = { userId: 'user-id-1' };
      const mockResponse = {} as Response;
      const mockError = new UnprocessableEntityException('Validation failed');

      sessionRepository.create.mockRejectedValue(mockError);

      await expect(service.createSession(mockCreateDto, mockResponse)).rejects.toThrow(UnprocessableEntityException);
    });

    it('should handle a generic error', async () => {
      const mockCreateDto: CreateSessionDto = { userId: 'user-id-1' };
      const mockResponse = {} as Response;
      const mockError = new Error('Some generic error');

      sessionRepository.create.mockRejectedValue(mockError);

      const result = await service.createSession(mockCreateDto, mockResponse);

      expect(result).toEqual({ status: 500, message: 'Some generic error' });
    });
  });

  describe('findSessionsByUser', () => {
    it('should find sessions for a given user', async () => {
      const userId = 'user-id-1';
      const mockSessions = [{ _id: 's1' }, { _id: 's2' }];

      sessionRepository.find.mockResolvedValue(mockSessions as any);

      const result = await service.findSessionsByUser(userId);

      expect(sessionRepository.find).toHaveBeenCalledWith({ userId, revoked: false });
      expect(result).toEqual({ status: 200, data: mockSessions });
    });

    it('should handle errors when finding sessions', async () => {
      const userId = 'user-id-1';
      const mockError = new Error('Database error');

      sessionRepository.find.mockRejectedValue(mockError);

      const result = await service.findSessionsByUser(userId);

      expect(result).toEqual({ status: 500, message: 'Database error' });
    });
  });

  describe('revokeSession', () => {
    it('should revoke a single session', async () => {
      const sessionId = 'session-id-1';
      const mockRevokedSession = { _id: sessionId, revoked: true };

      sessionRepository.findOneAndUpdate.mockResolvedValue(mockRevokedSession as any);

      const result = await service.revokeSession(sessionId);

      expect(sessionRepository.findOneAndUpdate).toHaveBeenCalledWith({ _id: sessionId }, { revoked: true });
      expect(result).toEqual({ status: 200, data: mockRevokedSession });
    });

    it('should handle errors when revoking a session', async () => {
      const sessionId = 'session-id-1';
      const mockError = new Error('Revoke failed');

      sessionRepository.findOneAndUpdate.mockRejectedValue(mockError);

      const result = await service.revokeSession(sessionId);

      expect(result).toEqual({ status: 500, message: 'Revoke failed' });
    });
  });

  describe('revokeAllUserSessions', () => {
    it('should revoke all sessions for a user', async () => {
      const userId = 'user-id-1';
      const mockUpdateResult = { modifiedCount: 3 };

      sessionRepository.updateMany.mockResolvedValue(mockUpdateResult as any);

      const result = await service.revokeAllUserSessions(userId);

      expect(sessionRepository.updateMany).toHaveBeenCalledWith({ userId }, { revoked: true });
      expect(result).toEqual({ status: 200, modifiedCount: 3 });
    });

    it('should handle errors when revoking all sessions', async () => {
      const userId = 'user-id-1';
      const mockError = new Error('Bulk revoke failed');

      sessionRepository.updateMany.mockRejectedValue(mockError);

      const result = await service.revokeAllUserSessions(userId);

      expect(result).toEqual({ status: 500, message: 'Bulk revoke failed' });
    });
  });

  describe('updateSession', () => {
    it('should update a session successfully', async () => {
      const sessionId = 'session-id-1';
      const mockUpdateDto: UpdateSessionDto = {
        lastSeenAt: new Date(),
      };
      const mockUpdatedSession = { _id: sessionId, ...mockUpdateDto };

      sessionRepository.findOneAndUpdate.mockResolvedValue(mockUpdatedSession as any);

      const result = await service.updateSession(sessionId, mockUpdateDto);

      expect(sessionRepository.findOneAndUpdate).toHaveBeenCalledWith({ _id: sessionId }, mockUpdateDto);
      expect(result).toEqual({ status: 200, data: mockUpdatedSession });
    });

    it('should handle errors when updating a session', async () => {
      const sessionId = 'session-id-1';
      const mockUpdateDto: UpdateSessionDto = { lastSeenAt: new Date() };
      const mockError = new Error('Update failed');

      sessionRepository.findOneAndUpdate.mockRejectedValue(mockError);

      const result = await service.updateSession(sessionId, mockUpdateDto);

      expect(result).toEqual({ status: 500, message: 'Update failed' });
    });
  });

  describe('getById', () => {
    it('should get a session by ID', async () => {
      const sessionId = 'session-id-1';
      const mockSession = { _id: sessionId };

      sessionRepository.findOne.mockResolvedValue(mockSession as any);

      const result = await service.getById(sessionId);

      expect(sessionRepository.findOne).toHaveBeenCalledWith({ _id: sessionId });
      expect(result).toEqual({ status: 200, data: mockSession });
    });

    it('should handle errors when getting a session by ID', async () => {
      const sessionId = 'session-id-1';
      const mockError = new Error('Find failed');

      sessionRepository.findOne.mockRejectedValue(mockError);

      const result = await service.getById(sessionId);

      expect(result).toEqual({ status: 500, message: 'Find failed' });
    });
  });

  describe('findActiveSession', () => {
    it('should find an active session based on criteria', async () => {
      const userId = 'user-id-1';
      const ip = '127.0.0.1';
      const userAgent = 'mock-agent';
      const mockSession = { _id: 's1', userId, ip, userAgent, revoked: false };

      sessionRepository.findOne.mockResolvedValue(mockSession as any);

      const result = await service.findActiveSession(userId, ip, userAgent);

      expect(sessionRepository.findOne).toHaveBeenCalledWith({
        userId,
        ip,
        userAgent,
        revoked: false,
      });
      expect(result).toEqual({ status: 200, data: mockSession });
    });

    it('should handle errors when finding an active session', async () => {
      const mockError = new Error('Find failed');

      sessionRepository.findOne.mockRejectedValue(mockError);

      const result = await service.findActiveSession('u1', '127.0.0.1', 'agent');

      expect(result).toEqual({ status: 500, message: 'Find failed' });
    });
  });

  describe('updateLastSeen', () => {
    it('should update the lastSeenAt timestamp', async () => {
      const sessionId = 'session-id-1';
      const timestamp = new Date();

      sessionRepository.findOneAndUpdate.mockResolvedValue({ _id: sessionId, lastSeenAt: timestamp } as any);

      await service.updateLastSeen(sessionId, timestamp);

      expect(sessionRepository.findOneAndUpdate).toHaveBeenCalledWith(
        { _id: sessionId },
        { $set: { lastSeenAt: timestamp } }
      );
    });

    it('should not throw on error (silent catch)', async () => {
      sessionRepository.findOneAndUpdate.mockRejectedValue(new Error('Update failed'));
      await expect(service.updateLastSeen('s1', new Date())).resolves.not.toThrow();
    });
  });
});
