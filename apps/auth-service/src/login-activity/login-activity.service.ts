import * as geoip from 'geoip-lite';
import { Injectable, UnprocessableEntityException } from '@nestjs/common';
import { CreateLoginActivityDto } from './dto/create-login-activity.dto/create-login-activity.dto';
import { LoginActivityRepository } from './repositories/login-activity.repository';

@Injectable()
export class LoginActivityService {
  constructor(
    private readonly loginActivityRepo: LoginActivityRepository,
  ) {}

  async logActivity(dto: CreateLoginActivityDto) {
    try {
      const sanitizedDto = {
        ...dto,
        isNewLocation: dto.isNewLocation ?? undefined,
      };

      const loggedActivity = await this.loginActivityRepo.create(sanitizedDto);

      return {
        status: 200,
        data: loggedActivity
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

  async getLogsForUser(userId: string) {
    return await this.loginActivityRepo.findOne({ userId });
  }

  async detectAnomaly(userId: string, ipAddress: string) {
    const geo = geoip.lookup(ipAddress);
    const lastLogin = await this.loginActivityRepo.findOne({ userId, status: 'success' });

    const isNewLocation = lastLogin && geo && (
      lastLogin.location?.country !== geo.country ||
      lastLogin.location?.city !== geo.city
    );

    return {
      location: geo
        ? { country: geo.country, city: geo.city, region: geo.region }
        : undefined,
      isNewLocation
    };
  }
}
