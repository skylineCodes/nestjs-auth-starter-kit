import { Response } from 'express';
import { CreateSessionDto } from './dto/create-session.dto';
import { UpdateSessionDto } from './dto/update-session.dto';
import { SessionRepository } from './repositories/session.repository';
import { Injectable, UnprocessableEntityException } from '@nestjs/common';

@Injectable()
export class SessionsService {
  constructor(
    private readonly sessionsRepo: SessionRepository,
  ) { }

  async createSession(dto: CreateSessionDto, response: Response) {
    try {
      const newSession = await this.sessionsRepo.create({ ...dto, lastSeenAt: new Date(), } as any);

      return {
        status: 200,
        message: 'Session created successfully!',
        data: newSession
      };
    } catch (error) {
      if (error.code === '11000') {
        return {
          status: 500,
          message: error.message,
        };
      }

      if (error instanceof UnprocessableEntityException) {
        throw error;
      }

      return {
        status: 500,
        message: error.message,
      };
    }
  }

  async findSessionsByUser(userId: string) {
    try {
      const sessions = await this.sessionsRepo.find({ userId, revoked: false });

      return {
        status: 200,
        data: sessions
      }
    } catch (error) {
      if (error.code === '11000') {
        return {
          status: 500,
          message: error.message,
        };
      }

      if (error instanceof UnprocessableEntityException) {
        throw error;
      }

      return {
        status: 500,
        message: error.message,
      };
    }
  }

  async revokeSession(sessionId: any) {
    try {
      const sessions = await this.sessionsRepo.findOneAndUpdate({ _id: sessionId }, { revoked: true });

      return {
        status: 200,
        data: sessions
      }
    } catch (error) {
      if (error.code === '11000') {
        return {
          status: 500,
          message: error.message,
        };
      }

      if (error instanceof UnprocessableEntityException) {
        throw error;
      }

      return {
        status: 500,
        message: error.message,
      };
    }
  }

  async revokeAllUserSessions(userId: string) {
    try {
      const sessions = await this.sessionsRepo.updateMany({ userId }, { revoked: true });

      return {
        status: 200,
        modifiedCount: sessions.modifiedCount
      }
    } catch (error) {
      if (error.code === '11000') {
        return {
          status: 500,
          message: error.message,
        };
      }

      if (error instanceof UnprocessableEntityException) {
        throw error;
      }

      return {
        status: 500,
        message: error.message,
      };
    }
  }

  async updateSession(sessionId: string, update: UpdateSessionDto) {
    try {
      const sessions = await this.sessionsRepo.findOneAndUpdate({ _id: sessionId }, update);

      return {
        status: 200,
        data: sessions
      }
    } catch (error) {
      if (error.code === '11000') {
        return {
          status: 500,
          message: error.message,
        };
      }

      if (error instanceof UnprocessableEntityException) {
        throw error;
      }

      return {
        status: 500,
        message: error.message,
      };
    }
  }

  async getById(sessionId: string) {
    try {
      const sessions = await this.sessionsRepo.findOne({ _id: sessionId });

      return {
        status: 200,
        data: sessions
      }
    } catch (error) {
      if (error.code === '11000') {
        return {
          status: 500,
          message: error.message,
        };
      }

      if (error instanceof UnprocessableEntityException) {
        throw error;
      }

      return {
        status: 500,
        message: error.message,
      };
    }
  }

  async findActiveSession(userId: string, ip: string | undefined, userAgent: string | undefined) {
    try {
      const session = await this.sessionsRepo.findOne({
        userId,
        ip,
        userAgent,
        revoked: false,
      });

      return {
        status: 200,
        data: session,
      }
    } catch (error) {
      if (error.code === '11000') {
        return {
          status: 500,
          message: error.message,
        };
      }

      if (error instanceof UnprocessableEntityException) {
        throw error;
      }

      return {
        status: 500,
        message: error.message,
      };
    }
  }

  async updateLastSeen(sessionId: string, timestamp: Date): Promise<void> {
    try {
      await this.sessionsRepo.findOneAndUpdate(
        { _id: sessionId },
        { $set: { lastSeenAt: timestamp } }
      );

      return;
    } catch (error) { }
  }
}