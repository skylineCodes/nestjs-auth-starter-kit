import { Controller, Delete, Get, Param, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../strategies/jwt-auth.guard';
import { SessionsService } from './sessions.service';
import { ApiOkResponse, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';

@ApiTags('Session')
@Controller('auth/sessions')
@UseGuards(JwtAuthGuard)
export class SessionsController {
  constructor(private readonly sessionsService: SessionsService) {}

  @Get()
  @ApiOperation({ summary: 'Fetch Session' })
  @ApiOkResponse({
    description: 'List of all user login sessions',
    schema: {
      example: {
        "status": 200,
        "data": [
          {
            "_id": "688f7d9c8290ba6e120d0cfb",
            "userId": "688f7d648290ba6e120d0cda",
            "ipAddress": "::ffff:172.19.0.8",
            "userAgent": "Other 0.0.0 / Other 0.0.0",
            "deviceName": "Other 0.0.0",
            "isCurrentDevice": false,
            "isSuspicious": false,
            "revoked": false,
            "lastSeenAt": "2025-08-03T17:59:17.018Z",
            "createdAt": "2025-08-03T15:17:48.699Z",
            "updatedAt": "2025-08-03T17:59:17.019Z",
            "__v": 0
          },
          {
            "_id": "688fa37531dc590a8d8f4542",
            "userId": "688f7d648290ba6e120d0cda",
            "ipAddress": "::ffff:172.19.0.8",
            "userAgent": "Other 0.0.0 / Other 0.0.0",
            "deviceName": "Other 0.0.0",
            "isCurrentDevice": false,
            "isSuspicious": false,
            "revoked": false,
            "lastSeenAt": "2025-08-03T18:08:52.628Z",
            "createdAt": "2025-08-03T17:59:17.267Z",
            "updatedAt": "2025-08-03T18:08:52.630Z",
            "__v": 0
          },
          {
            "_id": "688fa5bbb060cdf26df52124",
            "userId": "688f7d648290ba6e120d0cda",
            "ipAddress": "::ffff:172.19.0.8",
            "userAgent": "Other 0.0.0 / Other 0.0.0",
            "deviceName": "Other 0.0.0",
            "isCurrentDevice": false,
            "isSuspicious": false,
            "revoked": false,
            "lastSeenAt": "2025-08-03T18:09:02.253Z",
            "createdAt": "2025-08-03T18:08:59.723Z",
            "updatedAt": "2025-08-03T18:09:02.254Z",
            "__v": 0
          },
        ]
      }
    }
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized',
  })
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
