import * as bcrypt from 'bcrypt';
import { randomInt } from 'crypto';
import { LoginDto } from './dto/login.dto';
import { Request, Response } from 'express';
import { LogoutDto } from './dto/logout.dto';
import { RegisterDto } from './dto/register.dto';
import { NOTIFICATIONS_SERVICE } from '@app/common';
import { ClientProxy } from '@nestjs/microservices';
import { UsersService } from './users/users.service';
import { SessionsService } from './sessions/sessions.service';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResendResetPasswordDto } from './dto/resend-reset-password';
import { LoginActivityService } from './login-activity/login-activity.service';
import { BadRequestException, ConflictException, Inject, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';

@Injectable()
export class AuthServiceService {
  constructor(
    private readonly usersService: UsersService,
    private readonly sessionsService: SessionsService,
    private readonly loginActivityService: LoginActivityService,
    @Inject(NOTIFICATIONS_SERVICE)
    private readonly notificationsService: ClientProxy,
  ) {}

  async register(dto: RegisterDto, response: Response) {
    try {
      const enrichedDto = {
        ...dto,
      };

      const registerUser = await this.usersService.create(enrichedDto, response);
  
      return {
        status: 200,
        message: 'Account created successfully!',
      };
    } catch(error) {
      console.log(error);
      if (error instanceof ConflictException || error instanceof BadRequestException) {
        throw error;
      }

      return {
        status: 500,
        message: error.message,
      };
    }
  }

  async login(dto: LoginDto, request: Request, response: Response) {
    try {
      const user: any = await this.usersService.validateUserCredentialsByEmail(dto.email, dto.password, request);

      if (user?.status !== 200 || user?.data === null) throw new Error(user?.message);

      if (request?.ip) {
      const { location, isNewLocation } = await this.loginActivityService.detectAnomaly(user?.data?._id, request?.ip);

        await this.loginActivityService.logActivity({
          userId: user?.data?._id,
          status: 'success',
          ipAddress: request?.ip,
          userAgent: request.get('User-Agent'),
          location,
          isNewLocation
        });
      }

      await this.usersService.updateLastLogin(user?.data._id);
      
      // Generate session ID (cookie-based)
      const sessionData = await this.usersService.setSessionToken(user?.data, request, response);

      // Generate access token (cookie-based)
      await this.usersService.setAuthToken(user?.data, sessionData?.data, response);

      // Generate refresh token (cookie-based)
      await this.usersService.setRefreshToken(user?.data, response);

      return {
        status: 200,
        message: 'User logged in successfully!',
      };
    } catch(error) {
      return {
        status: 500,
        message: error.message,
      };
    }
  }

  async refreshToken(request: Request, response: Response) {
    const token = request.cookies['refreshToken'];

    if (!token) throw new UnauthorizedException('Missing refresh token');

    try {
      const payload: any = await this.usersService.verifyRefreshToken(token);

      const user = {
        _id: payload?.sub,
        type: payload?.type
      }

      // Generate session ID (cookie-based)
      const sessionData = await this.usersService.setSessionToken(user, request, response);

      // Generate access token (cookie-based)
      await this.usersService.setAuthToken(user, sessionData?.data, response);

      // Generate refresh token (cookie-based)
      await this.usersService.setRefreshToken(user, response);
      
      return {
        status: 200,
        message: 'Refresh token generated successfully!',
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async logout(dto: LogoutDto, request: Request | any, response: Response) {
    const currentSessionId = request.cookies?.SessionId;

    console.log('dto_session', dto);
    
    if (dto.sessionId) {
      console.log('dto_session', dto);
      // Logging out a different device — only revoke the session
      await this.sessionsService.revokeSession(dto.sessionId);
      
      return {
        status: 200,
        message: 'Device session revoked successfully',
      };
    } else if (currentSessionId && dto.sessionId === null) {
      console.log('currentSessionId', currentSessionId);
      // Revoke only the current session
      await this.sessionsService.revokeSession(currentSessionId);

      // Only clear cookies for current device
      response.clearCookie('Authentication', { path: '/', httpOnly: true, sameSite: 'strict' });
      response.clearCookie('refreshToken', { path: '/', httpOnly: true, sameSite: 'strict' });
      response.clearCookie('SessionId', { path: '/', httpOnly: true, sameSite: 'strict' });

      return {
        status: 200,
        message: 'Logged out successfully',
      };
    }

    if (dto.logoutAll === true) {
      // Revoke all sessions (including current one)
      await this.sessionsService.revokeAllUserSessions(request?.user?._id);

      // Only clear cookies for current device
      response.clearCookie('Authentication', { path: '/', httpOnly: true, sameSite: 'strict' });
      response.clearCookie('refreshToken', { path: '/', httpOnly: true, sameSite: 'strict' });
      response.clearCookie('SessionId', { path: '/', httpOnly: true, sameSite: 'strict' });

      return {
        status: 200,
        message: 'Logged out all sessions successfully',
      };
    }
  }
  

  async forgotPassword(dto: ForgotPasswordDto) {
    const user: any = await this.usersService.getUserByEmail(dto.email);
    if (!user) throw new NotFoundException('User not found');
  
    // Generate 6-digit OTP
    const otp = randomInt(100000, 999999).toString();
  
    // Store OTP and expiry in DB
    await this.usersService.setPasswordResetOtp(user.data?._id, otp);

    const html = `<!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Your One-Time Password (OTP)</title>
      </head>
      <body style="font-family: 'Inter', sans-serif; background-color: #f9fafb; padding: 2rem;">
        <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 0.5rem; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
          <div style="background-color: #2563eb; color: white; text-align: center; padding: 1rem 2rem;">
            <h1 style="font-size: 1.5rem; font-weight: bold;">Password Reset Request</h1>
          </div>
          <div style="padding: 2rem;">
            <p>Hi there,</p>
            <p>You recently requested a password reset for your account on <strong>Auth kit</strong>.</p>
            <p style="margin-top: 1rem;">Your One-Time Password (OTP) is:</p>
            <div style="font-size: 2rem; font-weight: bold; background-color: #f3f4f6; padding: 1rem; text-align: center; border-radius: 0.5rem; margin: 1rem 0; letter-spacing: 4px;">
              ${otp}
            </div>
            <p>This code is valid for <strong>15 minutes</strong>.</p>
            <p>If you did not request this, please ignore this email.</p>
            <p>Thank you,<br/><strong>FitFlow Team</strong></p>
          </div>
        </div>
      </body>
      </html>`;
  
    const mailOptions = {
      email: dto.email,
      subject: 'Password Reset OTP',
      html,
    };
  
    this.notificationsService.emit('notify_email', mailOptions);
  
    return {
      status: 200,
      message: 'Password reset OTP sent to email',
    };
  }

  async resetPassword(dto: { otp: string; newPassword: string }) {
    try {
      const user: any = await this.usersService.getUserByOtp(dto.otp);

      if (!user || !user?.data?.resetOtp || !user.data?.resetOtpExpires)
        throw new UnauthorizedException('Invalid or expired OTP');

      await this.usersService.updateUserProfile(user?.data._id, {
        otpRequestCount: 0,
      });

      const isOtpValid =
        user?.data?.resetOtp === dto.otp &&
        new Date(user?.data.resetOtpExpires) > new Date();

      if (!isOtpValid)
        throw new UnauthorizedException('Invalid or expired OTP');

      const passwordHash = await bcrypt.hash(dto.newPassword, 10);

      await this.usersService.updateUserProfile(user?.data._id, {
        passwordHash,
        resetOtp: null,
        resetOtpExpires: null,
        otpRequestCount: 0,
        otpRequestWindowStart: null,
      });

      const html = `<!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Your Password Has Been Reset</title>
        </head>
        <body style="font-family: 'Inter', sans-serif; background-color: #f9fafb; padding: 2rem;">
          <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 0.5rem; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <div style="background-color: #16a34a; color: white; text-align: center; padding: 1rem 2rem;">
              <h1 style="font-size: 1.5rem; font-weight: bold;">Password Successfully Reset!</h1>
            </div>
            <div style="padding: 2rem;">
              <p>Hi there,</p>
              <p>This email confirms that the password for your account has been successfully changed.</p>
              <div style="background-color: #fef2f2; border: 1px solid #fecaca; padding: 1rem; border-radius: 0.5rem;">
                <p><strong>Important Security Notice:</strong></p>
                <ul>
                  <li>If you <strong>did NOT</strong> perform this password change, contact support immediately.</li>
                  <li>Email: <a href="mailto:support@fitflow.com">support@fitflow.com</a></li>
                </ul>
              </div>
              <p style="margin-top: 1rem; font-size: 0.875rem; color: #4b5563;">
                This password change occurred on: <strong>${new Date().toLocaleString('en-US', { timeZone: 'Africa/Lagos' })}</strong>
              </p>
            </div>
            <div style="background-color: #f3f4f6; padding: 1rem; text-align: center; font-size: 0.875rem; color: #6b7280;">
              <p>Thank you,</p>
              <p><strong>FitFlow Team</strong></p>
            </div>
          </div>
        </body>
        </html>`;

        const mailOptions = {
          email: user.data.email,
          subject: 'Password Reset Confirmation',
          html,
        };
      
        this.notificationsService.emit('notify_email', mailOptions);

      return {
        status: 200,
        message: 'Password reset successful',
      };
    } catch (error) {
      throw new UnauthorizedException(error.message);
    }
  }

  async resendResetOtp(dto: ResendResetPasswordDto) {
    const user: any = await this.usersService.getUserByEmail(dto.email);
    if (!user) throw new NotFoundException('User not found');
  
    const otp = (user.data?.resetOtp && user.data?.resetOtpExpires > new Date())
      ? user?.data?.resetOtp
      : randomInt(100000, 999999).toString();
  
    await this.usersService.setPasswordResetOtp(user.data?._id, otp);
  
    const html = `<!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Your One-Time Password (OTP)</title>
      </head>
      <body style="font-family: 'Inter', sans-serif; background-color: #f9fafb; padding: 2rem;">
        <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 0.5rem; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
          <div style="background-color: #2563eb; color: white; text-align: center; padding: 1rem 2rem;">
            <h1 style="font-size: 1.5rem; font-weight: bold;">Password Reset Request</h1>
          </div>
          <div style="padding: 2rem;">
            <p>Hi there,</p>
            <p>You recently requested a password reset for your account on <strong>Auth kit</strong>.</p>
            <p style="margin-top: 1rem;">Your One-Time Password (OTP) is:</p>
            <div style="font-size: 2rem; font-weight: bold; background-color: #f3f4f6; padding: 1rem; text-align: center; border-radius: 0.5rem; margin: 1rem 0; letter-spacing: 4px;">
              ${otp}
            </div>
            <p>This code is valid for <strong>15 minutes</strong>.</p>
            <p>If you did not request this, please ignore this email.</p>
            <p>Thank you,<br/><strong>FitFlow Team</strong></p>
          </div>
        </div>
      </body>
      </html>`;
  
    const mailOptions = {
      email: dto.email,
      subject: 'Password Reset OTP',
      html,
    };
  
    this.notificationsService.emit('notify_email', mailOptions);
  
    return {
      status: 200,
      message: 'OTP resent successfully',
    };
  }
}
