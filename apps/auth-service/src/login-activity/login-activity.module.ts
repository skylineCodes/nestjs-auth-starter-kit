import { Module } from '@nestjs/common';
import { LoginActivityService } from './login-activity.service';
import { LoginActivityController } from './login-activity.controller';
import { DatabaseModule } from '@app/common';
import { LoginActivity, LoginActivitySchema } from './models/login-activity.schema/login-activity.schema';
import { LoginActivityRepository } from './repositories/login-activity.repository';

@Module({
  imports: [
    DatabaseModule,
    DatabaseModule.forFeature([
      { name: LoginActivity.name, schema: LoginActivitySchema },
    ]),
  ],
  providers: [LoginActivityService, LoginActivityRepository],
  controllers: [LoginActivityController],
  exports: [LoginActivityService]
})
export class LoginActivityModule {}
