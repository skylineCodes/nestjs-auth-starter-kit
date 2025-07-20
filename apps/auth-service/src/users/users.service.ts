import * as bcrypt from 'bcrypt';
import * as useragent from 'useragent';
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
      now.getTime() - new Date(user.data?.otpRequestWindowStart).getTime() < 60 * 60 * 1000;
  
    // Too many attempts?
    if (isSameWindow && user.data?.otpRequestCount >= 5) {
      throw new ForbiddenException('Too many OTP requests. Try again later.');
    }
  
    // Determine new values
    const update: any = {
      resetOtp: otp,
      resetOtpExpires: new Date(Date.now() + 15 * 60 * 1000),
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

      if (!user) throw new UnauthorizedException('User not found');

      const isPasswordValid = await bcrypt.compare(password, user.data.passwordHash);
      if (!isPasswordValid) {
        await this.loginActivityService.logActivity({
          userId: user?.data?._id,
          status: 'failed',
          ipAddress: request?.ip,
          userAgent: request?.get('User-Agent'),
          reason: 'Invalid credentials'
        });

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
    try {
      const user: any = await this.getUserByPhone(phone);
      if (!user) throw new UnauthorizedException('User not found');

      const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
      if (!isPasswordValid) throw new UnauthorizedException('Invalid credentials');

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
      const allUsers = this.userRepo.find();

      return {
        status: 200,
        data: allUsers,
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

  async setAuthToken(
    user: User | any,
    sessionData: any,
    response: Response,
  ): Promise<void> {
    try {
      const accessToken = this.generateAccessToken(user._id, user.type, sessionData?._id.toString());

      const accessTokenExpiry = parseInt(
        this.configService.get<string>('JWT_ACCESS_EXPIRY') as any,
        10
      );
      
      if (isNaN(accessTokenExpiry)) {
        throw new Error('JWT_ACCESS_EXPIRY must be a number (in ms)');
      }

      response.cookie('Authentication', accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        // maxAge: 60 * 1000 // 60 seconds
        maxAge: accessTokenExpiry,
      });

      return;
    } catch (error) {
      // Handle specific error scenarios if necessary
      console.error('Error setting auth token:', error);
      throw new Error('Failed to set authentication token');
    }
  }

  async setSessionToken(
    user: User | any,
    request: Request,
    response: Response,
  ): Promise<any> {
    try {
      // Save session
      const ip = request.ip || request?.connection.remoteAddress;
      const agent = useragent.parse(request.headers['user-agent']);

      const existingSession = await this.sessionsService.findActiveSession(user._id, request.ip, request.headers['user-agent']);

      let session: any;

      if (existingSession?.data !== null) {
        session = existingSession;
      } else {
        session = await this.sessionsService.createSession({
          userId: user._id,
          ipAddress: ip,
          userAgent: agent.toString(),
          deviceName: agent.device.toString(),
          lastSeenAt: new Date(),
        }, response);
      }

      response.cookie('SessionId', session.data?._id, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      return {
        data: session.data?._id
      }
    } catch (error) {
      // Handle specific error scenarios if necessary
      console.error('Error setting auth token:', error);
      throw new Error('Failed to set authentication token');
    }
  }

  async setRefreshToken(
    user: User | any,
    response: Response,
  ): Promise<void> {
    try {
      const refreshToken = this.generateRefreshToken(user._id);

      const refreshExpiry = parseInt(
        this.configService.get<string>('JWT_REFRESH_EXPIRY') as any,
        10
      );
      
      if (isNaN(refreshExpiry)) {
        throw new Error('JWT_REFRESH_EXPIRY must be a number (in ms)');
      }
      
      response.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        // maxAge: 120 * 1000 // 120 milliseconds
        maxAge: refreshExpiry,
      });

      return;
    } catch (error) {
      // Handle specific error scenarios if necessary
      console.error('Error setting refresh token:', error);
      throw new Error('Failed to set authentication token');
    }
  }

  async verifyRefreshToken(
    token: any,
  ): Promise<void> {
    try {
      const payload = this.jwtService.verifyAsync(
        token,
        {
          secret: this.configService.get('JWT_REFRESH_SECRET'),
        },
      )

      return payload;
    } catch (error) {
      throw new Error('Invalid refresh token');
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
        expiresIn: expiryInSeconds
      },
    )
  }

  private generateRefreshToken(userId: string) {
    const expiryInSeconds = parseInt(
      this.configService.get<string>('JWT_REFRESH_EXPIRY') as any,
      10
    );

    return this.jwtService.sign(
      { sub: userId },
      {
        secret: this.configService.get('JWT_REFRESH_SECRET'),
        expiresIn: expiryInSeconds
      },
    )
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
