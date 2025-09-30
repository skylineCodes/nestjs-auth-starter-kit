import * as UAParser from 'ua-parser-js';
import { Injectable, UnprocessableEntityException } from '@nestjs/common';
import { CreateLoginActivityDto } from './dto/create-login-activity.dto';
import { LoginActivityRepository } from './repositories/login-activity.repository';
import { IpLocationRepository } from './repositories/ip-location.repository';

@Injectable()
export class LoginActivityService {
  constructor(
    private readonly loginActivityRepository: LoginActivityRepository,
    private readonly ipLocationRepository: IpLocationRepository,
  ) {}

  async logActivity(dto: CreateLoginActivityDto) {
    try {
      const sanitizedDto = {
        ...dto,
        userId: dto.userId!,
        ipAddress: dto.ipAddress ?? undefined,
        isNewLocation: dto.isNewLocation ?? undefined,
        isSuspicious: dto.isSuspicious ?? undefined,
        location: dto.location ?? undefined,
      };

      const loggedActivity = await this.loginActivityRepository.create(sanitizedDto);

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

  async getLogsForUser(userId: string, page = 1, pageSize = 10) {
    try{
      const loginActivity = await this.loginActivityRepository.find({ userId: String(userId) }, { sort: { loginAt: -1 }, page, pageSize });

      return {
        status: 200,
        data: loginActivity
      };
    } catch(error) {
      return {
        status: 500,
        message: error.message
      }
    }
  }

  async detectAnomaly(userId: string, ipAddress: string | any,  userAgent: any) {
    // Normalize IPv6-mapped IPv4 addresses
    const normalizedIp = ipAddress.startsWith("::ffff:")
      ? ipAddress.replace("::ffff:", "")
      : ipAddress;

    // 1️⃣ Check cache in DB
    let cachedLocation = await this.ipLocationRepository.findOne({ ip: normalizedIp });

    // Parse device from user agent
    const parser = new UAParser.UAParser(userAgent);
    const uaResult = parser.getResult();
    const currentDevice = {
      browser: uaResult.browser.name,
      os: uaResult.os.name,
      type: uaResult.device.type || "desktop",
    };

    // console.log('cachedLocation', cachedLocation);

    // 2️⃣ If not cached, fetch from IPinfo (or geoip-lite fallback)
    if (!cachedLocation) {
      const geo = await this.lookupIp(normalizedIp);

      if (geo) {
        cachedLocation = await this.ipLocationRepository.create({
          ip: normalizedIp,
          country: geo.country,
          city: geo.city,
          region: geo.region,
        });
      }
    }

    const lastLogin = await this.loginActivityRepository.findOne({ userId, status: 'success' });

    const isNewLocation =
    lastLogin &&
    cachedLocation &&
    (lastLogin.location?.country !== cachedLocation.country ||
      lastLogin.location?.city !== cachedLocation.city);

    // Compare device
    const isNewDevice =
      lastLogin &&
      lastLogin.device &&
      (lastLogin.device.browser !== currentDevice.browser ||
        lastLogin.device.os !== currentDevice.os ||
        lastLogin.device.type !== currentDevice.type);

    // Anomaly if new location OR new device
    const isSuspicious = !!(isNewLocation || isNewDevice);

    return {
      location: cachedLocation
        ? { country: cachedLocation.country, city: cachedLocation.city, region: cachedLocation.region }
        : undefined,
      device: currentDevice,
      isNewLocation,
      isNewDevice,
      isSuspicious,
    };
  }

  // async detectAnomaly(userId: string, ipAddress: string, userAgent: string) {
  //   // Normalize IPv6-mapped IPv4
  //   const normalizedIp = ipAddress.startsWith("::ffff:")
  //     ? ipAddress.replace("::ffff:", "")
  //     : ipAddress;

  //   // Get geo info
  //   const geo = await this.lookupIp(normalizedIp);

  //   // Parse device from user agent
  //   const parser = new UAParser(userAgent);
  //   const uaResult = parser.getResult();
  //   const currentDevice = {
  //     browser: uaResult.browser.name,
  //     os: uaResult.os.name,
  //     type: uaResult.device.type || "desktop",
  //   };

  //   // Get last successful login
  //   const lastLogin = await this.loginActivityRepository.findOne({
  //     userId,
  //     status: "success",
  //   });

  //   // Compare location
  //   const isNewLocation =
  //     lastLogin &&
  //     geo &&
  //     (lastLogin.location?.country !== geo.country ||
  //       lastLogin.location?.city !== geo.city);

  //   // Compare device
  //   const isNewDevice =
  //     lastLogin &&
  //     lastLogin.device &&
  //     (lastLogin.device.browser !== currentDevice.browser ||
  //       lastLogin.device.os !== currentDevice.os ||
  //       lastLogin.device.type !== currentDevice.type);

  //   // Anomaly if new location OR new device
  //   const isSuspicious = !!(isNewLocation || isNewDevice);

  //   return {
  //     location: geo
  //       ? { country: geo.country, city: geo.city, region: geo.region }
  //       : undefined,
  //     device: currentDevice,
  //     isNewLocation,
  //     isNewDevice,
  //     isSuspicious,
  //   };
  // }

  async lookupIp(ip: string) {
    const res = await fetch(`https://ipinfo.io/${ip}?token=${process.env.IPINFO_TOKEN}`);
    const data: any = await res.json();
    
    return {
      country: data.country,
      city: data.city,
      region: data.region,
      loc: data.loc,
    };
  }
}
