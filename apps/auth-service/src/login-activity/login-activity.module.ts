import { Module } from '@nestjs/common';
import { LoginActivityService } from './login-activity.service';
import { LoginActivityController } from './login-activity.controller';
import { DatabaseModule } from '@app/common';
import { LoginActivity, LoginActivitySchema } from './models/login-activity.schema';
import { LoginActivityRepository } from './repositories/login-activity.repository';
import { IpLocation, IpLocationSchema } from './models/ip-location.schema';
import { IpLocationRepository } from './repositories/ip-location.repository';

@Module({
  imports: [
    DatabaseModule,
    DatabaseModule.forFeature([
      { name: IpLocation.name, schema: IpLocationSchema },
      { name: LoginActivity.name, schema: LoginActivitySchema },
    ]),
  ],
  providers: [LoginActivityService, LoginActivityRepository, IpLocationRepository],
  controllers: [LoginActivityController],
  exports: [LoginActivityService]
})
export class LoginActivityModule {}
