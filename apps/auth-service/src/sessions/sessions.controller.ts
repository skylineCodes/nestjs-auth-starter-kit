import { Controller, Delete, Get, Param, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../strategies/jwt-auth.guard';
import { SessionsService } from './sessions.service';

@Controller('auth/sessions')
@UseGuards(JwtAuthGuard)
export class SessionsController {
  constructor(private readonly sessionsService: SessionsService) {}

  @Get()
  async getSessions(@Req() req) {
    return this.sessionsService.findSessionsByUser(req.user.token.sub);
  }

  @Delete(':id')
  async revokeSession(@Param('id') id: string) {
    return this.sessionsService.revokeSession(id);
  }

  @Delete()
  async revokeAll(@Req() req) {
    return this.sessionsService.revokeAllUserSessions(req.user.token.sub);
  }
}
