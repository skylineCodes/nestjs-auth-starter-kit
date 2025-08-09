import { ApiOkResponse, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { LoginDto } from './dto/login.dto';
import { LogoutDto } from './dto/logout.dto';
import { RegisterDto } from './dto/register.dto';
import { UserR } from './users/models/user.schema';
import { Request, Response } from 'express';
import { JwtAuthGuard } from './strategies/jwt-auth.guard';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { AuthServiceService } from './auth-service.service';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResendResetPasswordDto } from './dto/resend-reset-password';
import { LoginActivityService } from './login-activity/login-activity.service';
import { Body, Controller, Get, Param, Post, Req, Res, UseGuards } from '@nestjs/common';
import { MeResponseDto } from './dto/profile-response.dto';
import { LoginHistoryResponseDto } from './login-activity/dto/create-login-activity.dto/create-login-activity.dto';

@Controller('auth')
export class AuthServiceController {
  constructor(private readonly authServiceService: AuthServiceService, private readonly loginActivityService: LoginActivityService) {}

  @ApiTags('Auth')
  @Post('register')
  @ApiOperation({ summary: 'Create Account' })
  @ApiResponse({
    status: 200,
    description: 'Account created successfully!'
  })
  async register(@Body() dto: RegisterDto, @Res() response: Response) {
    const userResponse: UserR = await this.authServiceService.register(
      dto,
      response,
    );

    return response.status(userResponse.status).json(userResponse);
  }

  @ApiTags('Auth')
  @Post('login')
  @ApiOperation({ summary: 'Login' })
  @ApiResponse({
    status: 200,
    description: 'User logged in successfully!'
  })
  async login(@Body() dto: LoginDto, @Req() request: Request, @Res() response: Response) {
    const userResponse: UserR = await this.authServiceService.login(
      dto,
      request,
      response,
    );

    return response.status(userResponse.status).json(userResponse);
  }

  @ApiTags('Auth')
  @Post('refresh')
  @ApiOperation({ summary: 'Refresh Token' })
  @ApiResponse({
    status: 200,
    description: 'Refresh token generated successfully!'
  })
  async refresh(@Req() req: Request, @Res() response: Response) {
    const userResponse = await this.authServiceService.refreshToken(req, response);

    return response.status(200).json(userResponse);
  }

  @ApiTags('Auth')
  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @ApiOperation({ summary: 'Logout' })
  @ApiResponse({
    status: 200,
    description: 'Logged out successfully'
  })
  async logout(@Req() request, @Res() response: Response) {
    const sessionId = request.headers['x-session-id'] as string;

    const logoutAll = request.headers['x-logout-all'] === 'true';

    const payload: LogoutDto = {
      logoutAll,
      sessionId
    }

    const userResponse = await this.authServiceService.logout(payload, request, response);

    return response.status(userResponse.status).json(userResponse);
  }

  @ApiTags('Forgot Password')
  @Post('forgot-password')
  @ApiOperation({ summary: 'Forgot Password' })
  @ApiResponse({
    status: 200,
    description: 'Password reset OTP sent to email'
  })
  async forgotPassword(@Body() dto: ForgotPasswordDto, @Res() response: Response) {
    const userResponse = await this.authServiceService.forgotPassword(dto);

    return response.status(userResponse.status).json(userResponse);
  }

  @ApiTags('Forgot Password')
  @Post('reset-password')
  @ApiOperation({ summary: 'Reset Password' })
  @ApiResponse({
    status: 200,
    description: 'Password reset successful'
  })
  async resetPassword(@Body() dto: ResetPasswordDto, @Res() response: Response) {
    const userResponse = await this.authServiceService.resetPassword(dto);

    return response.status(userResponse.status).json(userResponse);
  }

  @Post('resend-reset-password')
  @ApiTags('Forgot Password')
  @ApiOperation({ summary: 'Resend Reset Password' })
  @ApiResponse({
    status: 200,
    description: 'OTP resent successfully'
  })
  async resendResetPassword(@Body() dto: ResendResetPasswordDto, @Res() response: Response) {
    const userResponse = await this.authServiceService.resendResetOtp(dto);

    return response.status(userResponse.status).json(userResponse);
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  @ApiTags('Profile')
  @ApiOperation({ summary: 'Fetch Profile' })
  @ApiResponse({
    status: 200,
    type: MeResponseDto
  })
  async getProfile(@Req() req: Request, @Res() response: Response) {
    const userResponse = {
      status: 200,
      data: req.user,
    };
    
    return response.status(userResponse.status).json(userResponse);
  }

  @UseGuards(JwtAuthGuard)
  @Get('audit-logs/:userId')
  @ApiTags('Audit Logs')
  @ApiOkResponse({
    type: LoginHistoryResponseDto,
    description: 'List of user login history records',
  })
  async getUserAuditLogs(@Param('userId') userId: string, @Res() response: Response) {
    const userResponse = await this.loginActivityService.getLogsForUser(userId);

    return response.status(userResponse.status).json(userResponse);
  }
}
