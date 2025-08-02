import { RegisterDto } from './dto/register.dto';
import { UserR } from './users/models/user.schema';
import { AuthServiceService } from './auth-service.service';
import { Body, Controller, Get, Param, Post, Req, Res, UseGuards } from '@nestjs/common';
import { Request, response, Response } from 'express';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from './strategies/jwt-auth.guard';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ResendResetPasswordDto } from './dto/resend-reset-password';
import { LogoutDto } from './dto/logout.dto';
import { LoginActivityService } from './login-activity/login-activity.service';

@Controller('auth')
export class AuthServiceController {
  constructor(private readonly authServiceService: AuthServiceService, private readonly loginActivityService: LoginActivityService) {}

  @Post('register')
  async register(@Body() dto: RegisterDto, @Res() response: Response) {
    const userResponse: UserR = await this.authServiceService.register(
      dto,
      response,
    );

    return response.status(userResponse.status).json(userResponse);
  }

  @Post('login')
  async login(@Body() dto: LoginDto, @Req() request: Request, @Res() response: Response) {
    const userResponse: UserR = await this.authServiceService.login(
      dto,
      request,
      response,
    );

    return response.status(userResponse.status).json(userResponse);
  }

  @Post('refresh')
  async refresh(@Req() req: Request, @Res() response: Response) {
    const userResponse = await this.authServiceService.refreshToken(req, response);

    return response.status(response.statusCode).json(userResponse);
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  async logout(@Req() request, @Res() response: Response) {
    const sessionId = request.headers['x-session-id'] as string;

    const logoutAll = request.headers['x-logout-all'] as boolean;

    const payload: LogoutDto = {
      logoutAll,
      sessionId
    }

    const userResponse = await this.authServiceService.logout(payload, request, response);

    return response.status(response.statusCode).json(userResponse);
  }

  @Post('forgot-password')
  async forgotPassword(@Body() dto: ForgotPasswordDto, @Res() response: Response) {
    const userResponse = await this.authServiceService.forgotPassword(dto);

    return response.status(response.statusCode).json(userResponse);
  }

  @Post('reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto, @Res() response: Response) {
    const userResponse = await this.authServiceService.resetPassword(dto);

    return response.status(response.statusCode).json(userResponse);
  }

  @Post('resend-reset-password')
  async resendResetPassword(@Body() dto: ResendResetPasswordDto, @Res() response: Response) {
    const userResponse = await this.authServiceService.resendResetOtp(dto);

    return response.status(response.statusCode).json(userResponse);
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  async getProfile(@Req() req: Request, @Res() response: Response) {
    const userResponse = {
      status: 200,
      data: req.user,
    };
    
    return response.status(response.statusCode).json(userResponse);
  }

  @Get('audit-logs/:userId')
  async getUserAuditLogs(@Param('userId') userId: string) {
    const userResponse = await this.loginActivityService.getLogsForUser(userId);

    return response.status(response.statusCode).json(userResponse);
  }
}
