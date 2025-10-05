import * as bcrypt from 'bcrypt';
import * as UAParser from 'ua-parser-js';
import { User } from './models/user.schema';
import { Request, Response } from 'express';
import { CreateUserDto } from './dto/create-user.dto';
import { UsersRepository } from './repositories/users.repository';
import { ForbiddenException, Injectable, UnauthorizedException, UnprocessableEntityException } from '@nestjs/common';
import { UpdateUserDto } from './dto/update-user.dto';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { SessionsService } from '../sessions/sessions.service';
import { LoginActivityService } from '../login-activity/login-activity.service';

@Injectable()
export class UsersService {

  constructor(
    private readonly jwtService: JwtService,
    private readonly userRepo: UsersRepository,
    private readonly configService: ConfigService,
    private readonly sessionsService: SessionsService,
    private readonly loginActivityService: LoginActivityService,
  ) {}

  async create(dto: CreateUserDto, response: Response) {
    try {
      await this.validateCreateUserDto(dto);

      const passwordHash = await bcrypt.hash(dto.password, 10);

      await this.userRepo.create({ ...dto, passwordHash } as any);

      return {
        status: 200,
        message: 'Account created successfully!',
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

  async getUserByEmail(email: string) {
    try {
      const userEmail = await this.userRepo.findOne({ email });

      return {
        status: 200,
        data: userEmail
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
  
  async getUserByOtp(resetOtp: string) {
    try {
      const userEmail = await this.userRepo.findOne({ resetOtp });

      return {
        status: 200,
        data: userEmail
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

  async getUserByPhone(phone: string) {
    try {
      const userPhone = await this.userRepo.findOne({ phone });

      return {
        status: 200,
        data: userPhone
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

  async getUserById(id: string) {
    try {
      const user = await this.userRepo.findOne({ _id: id });

      return {
        status: 200,
        data: user
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

  async checkIfUserExists(email: string) {
    try {
      const user = await this.getUserByEmail(email);

      return {
        status: 200,
        data: !!user?.data
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

  async setPasswordResetOtp(userId: string, otp: string) {
    const user: any = await this.getUserById(userId);
  
    const now = new Date();
    const isSameWindow =
      user.data?.otpRequestWindowStart &&
      now.getTime() - new Date(user.data?.otpRequestWindowStart).getTime() < 60 * 60 * 1000; // 1 hour
  
    // Too many attempts?
    if (isSameWindow && user.data?.otpRequestCount >= 5) {
      throw new ForbiddenException('Too many OTP requests. Try again later.');
    }
  
    // Determine new values
    const update: any = {
      resetOtp: otp,
      resetOtpExpires: new Date(Date.now() + 15 * 60 * 1000), // 15 mins
    };
  
    if (isSameWindow) {
      update.$inc = { otpRequestCount: 1 };
    } else {
      update.otpRequestCount = 1;
      update.otpRequestWindowStart = now;
    }
  
    // Update the user atomically
    return this.userRepo.findOneAndUpdate(
      { _id: userId },
      update,
      // { new: true } // optional: return updated user
    );
  }
  

  async validateUserCredentialsByEmail(email: string, password: string, request: Request) {
    try {
      const user: any = await this.getUserByEmail(email);

      if (!user || !user.data) {
        throw new UnauthorizedException('User not found');
      }

      const isPasswordValid = await bcrypt.compare(password, user.data.passwordHash);

      if (!isPasswordValid) {
        throw new UnauthorizedException('Invalid credentials');
      }

      return {
        status: 200,
        data: user?.data
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

  async validateUserCredentialsByPhone(phone: string, password: string) {
    // Check if a user with the provided phone number exists.
    const user: any = await this.getUserByPhone(phone);
    // If the user's data is null, it means no user was found.
    if (!user.data) {
      throw new UnauthorizedException('User not found');
    }

    // Compare the provided password with the user's hashed password.
    const isPasswordValid = await bcrypt.compare(password, user.data.passwordHash);
    // If the passwords do not match, throw an UnauthorizedException.
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // If validation is successful, return the user data.
    return {
      status: 200,
      data: user.data
    };
  }

  async updateLastLogin(userId: string) {
    try {
      this.userRepo.findOneAndUpdate(
        { _id: userId }, 
        { lastLoginAt: new Date() },
      );

      return {
        status: 200,
        message: 'Update successful!',
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

  async updateUserProfile(userId: string, dto: UpdateUserDto) {
    try {
      await this.userRepo.findOneAndUpdate(
        { _id: userId }, 
        { ...dto },
      );

      return {
        status: 200,
        message: 'Update successful!',
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

  async deactivateUser(userId: string) {
    try {
      this.userRepo.findOneAndUpdate(
        { _id: userId }, 
        { isActive: false },
      );

      return {
        status: 200,
        message: 'Update successful!',
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

  async getAllUsers() {
    try {
      // Await the asynchronous find() operation to get the user data
      const allUsers = await this.userRepo.find();

      return {
        status: 200,
        data: allUsers,
      };
    } catch (error) {
      // Handle duplicate key error (11000)
      if (error.code === '11000') {
        return {
          status: 500,
          message: error.message,
        };
      }

      // Re-throw specific exceptions if necessary
      if (error instanceof UnprocessableEntityException) {
        throw error;
      }
      
      // Handle other generic errors
      return {
        status: 500,
        message: error.message,
      };
    }
  }

  async setAuthToken(
    user: User | any,
    sessionData: any,
    response: Response,
  ): Promise<void> {
    try {
      const accessToken = this.generateAccessToken(user._id, user.type, sessionData?._id.toString());

      response.cookie('Authentication', accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        // maxAge: 60 * 1000 // 60 seconds
        // maxAge: accessTokenExpiry,
      });

      return;
    } catch (error) {
      // Handle specific error scenarios if necessary
      throw new Error('Failed to set authentication token');
    }
  }

  /**
   * Compare a raw refresh token to the stored hash
   */
  async compareRefreshTokenHash(token: string, storedHash?: string): Promise<boolean> {
    if (!storedHash) return false;
    return bcrypt.compare(token, storedHash);
  }

  async setSessionToken(
    user: User | any,
    request: Request,
    response: Response,
  ): Promise<any> {
    try {
      // Save session
      const forwarded = request.headers['x-forwarded-for'] as string;
      const ip = forwarded ? forwarded.split(',')[0].trim() : request.socket.remoteAddress;

      const userAgent = request.get('User-Agent');
  
      const parser = new UAParser.UAParser(request.headers['user-agent']);
      const uaResult = parser.getResult();

      const existingSession = await this.sessionsService.findActiveSession(user._id, ip, userAgent);

      let session: any;
      
      if (existingSession?.data !== null) {
        session = existingSession;
      } else {
        // console.log("I am still creating new session here...");
        const geo = await this.loginActivityService.lookupIp(ip as string);
        const locationDetails = { country: geo.country, city: geo.city, region: geo.region }

        session = await this.sessionsService.createSession({
          userId: user._id,
          ipAddress: ip,
          userAgent,
          deviceName: {
            browser: uaResult.browser.name,
            os: uaResult.os.name,
            type: uaResult.device.type || 'desktop'
          },
          location: locationDetails ?? undefined,
          lastSeenAt: new Date(),
        }, response);
      }

      response.cookie('SessionId', session.data?._id.toString(), {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        // maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      return {
        data: session.data?._id
      }
    } catch (error) {
      // Handle specific error scenarios if necessary
      throw new Error('Failed to set authentication token');
    }
  }

  async setRefreshToken(
    user: User | any,
    sessionData: any,
    response: Response,
  ): Promise<void> {
    try {
      const refreshToken = await this.generateRefreshToken(user._id, user.type, sessionData?._id.toString());
      
      response.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        // maxAge: 120 * 1000 // 120 milliseconds
        // maxAge: refreshExpiry,
      });

      return;
    } catch (error) {
      // Handle specific error scenarios if necessary
      throw new Error('Failed to set authentication token');
    }
  }

  async verifyRefreshToken(
    token: any,
  ): Promise<void> {
    try {
      const decodedToken = decodeURIComponent(token);
      const payload = this.jwtService.verify(
        decodedToken,
        {
          secret: this.configService.get('JWT_REFRESH_SECRET'),
          ignoreExpiration: true,
        },
      );

      const now = Math.floor(Date.now() / 1000);

      if (payload.exp && payload.exp < now) {
        throw new Error('Token has expired');
      }

      return payload;
    } catch (error) {
      throw new Error('Invalid refresh token');
    }
  }

  async verifyToken(
    token: any,
  ): Promise<void> {
    try {
      const payload = this.jwtService.verify(token, {
        secret: this.configService.get('JWT_ACCESS_SECRET'),
        ignoreExpiration: true,
      });

      const now = Math.floor(Date.now() / 1000);

      if (payload.exp && payload.exp < now) {
        throw new Error('Token has expired');
      }

      return payload;
    } catch (error) {
      throw new Error('Invalid or expired token');
    }
  }

  private generateAccessToken(userId: string, type: any, sessionId: string) {
    const expiryInSeconds = parseInt(
      this.configService.get<string>('JWT_ACCESS_EXPIRY') as any,
      10
    );

    return this.jwtService.sign(
      { sub: userId, type, sessionId },
      {
        secret: this.configService.get('JWT_ACCESS_SECRET'),
        // expiresIn: '2m'
        expiresIn: this.configService.get('JWT_ACCESS_EXPIRY'),
      },
    )
  }

  private async generateRefreshToken(userId: string, type: any, sessionId: string) {
    const expiryInSeconds = parseInt(
      this.configService.get<string>('JWT_REFRESH_EXPIRY') as any,
      10
    ); 

    const newHash = this.jwtService.sign(
      { sub: userId, type, sessionId },
      {
        secret: this.configService.get('JWT_REFRESH_SECRET'),
        expiresIn: this.configService.get('JWT_REFRESH_EXPIRY'),
      },
    )

    // Update session with the new refresh token hash
    await this.sessionsService.updateSession(sessionId, { currentRefreshHash: newHash, lastSeenAt: new Date(), revoked: false });

    return String(newHash);
  }

  generateResetToken(userId: string) {
    const expiryInSeconds = parseInt(
      this.configService.get<string>('JWT_RESET_EXPIRY') as any,
      10
    );

    return this.jwtService.sign(
      { sub: userId },
      {
        secret: this.configService.get('JWT_RESET_SECRET'),
        expiresIn: expiryInSeconds
      },
    )
  }

  private async validateCreateUserDto(dto: CreateUserDto) {
    const user = await this.userRepo.findOne({ email: dto.email });

    if (user) {
      throw new UnprocessableEntityException('Email already exists.');
    }

    return;
  }
}
