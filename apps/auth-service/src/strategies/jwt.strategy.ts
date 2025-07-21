import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { SessionsService } from '../sessions/sessions.service';
import { UsersService } from '../users/users.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly configService: ConfigService,
    private readonly sessionsService: SessionsService,
    private readonly usersService: UsersService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: any) => request?.cookies?.Authentication || request?.Authentication,
      ]),
      secretOrKey: configService.get<string>('JWT_ACCESS_SECRET', { infer: true }) as string,
    });
  }

  async validate(payload: any) {
    const { sessionId, sub: userId } = payload;

    if (!sessionId) {
      throw new UnauthorizedException('Session ID is missing from token');
    }

    const session: any = await this.sessionsService.getById(sessionId);

    if (!session || session.data.revoked) {
      throw new UnauthorizedException('Session has been revoked or does not exist');
    }

    const user = await this.usersService.getUserById(userId);

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const { passwordHash, ...safeUser }: any = user.data;

    return {
      user: safeUser,
      session: session?.data,
      token: payload,
    };
  }
}
