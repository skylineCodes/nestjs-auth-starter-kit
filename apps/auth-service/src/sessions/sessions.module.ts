import { Module } from '@nestjs/common';
import { DatabaseModule } from '@app/common';
import { Session, SessionSchema } from './models/session.schema';
import { SessionsService } from './sessions.service';
import { SessionRepository } from './repositories/session.repository';
import { SessionsController } from './sessions.controller';

@Module({
  imports: [
    DatabaseModule,
    DatabaseModule.forFeature([
      { name: Session.name, schema: SessionSchema },
    ]),
  ],
  providers: [SessionsService, SessionRepository],
  controllers: [SessionsController],
  exports: [SessionsService, SessionRepository]
})
export class SessionsModule {}
