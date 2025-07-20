import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { SessionsService } from '../sessions.service';

@Injectable()
export class SessionMiddleware implements NestMiddleware {
  constructor(private sessionsService: SessionsService) {}

  async use(req: Request, res: Response, next: NextFunction) {
    const sessionId = req.cookies?.SessionId || req.headers['x-session-id'];

    if (sessionId && typeof sessionId === 'string') {
      const session: any = await this.sessionsService.getById(sessionId);

      if (session && !session.data?.isRevoked) {
        req['session'] = session;
        await this.sessionsService.updateLastSeen(sessionId, new Date());
      }
    }

    next();
  }
}
