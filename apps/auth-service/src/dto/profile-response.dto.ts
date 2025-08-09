import { ApiProperty } from '@nestjs/swagger';

class UserDto {
  @ApiProperty() _id: string;
  @ApiProperty() firstName: string;
  @ApiProperty() lastName: string;
  @ApiProperty() email: string;
  @ApiProperty({ nullable: true }) resetOtp: string | null;
  @ApiProperty({ nullable: true }) resetOtpExpires: string | null;
  @ApiProperty() phone: string;
  @ApiProperty() type: string;
  @ApiProperty() isEmailVerified: boolean;
  @ApiProperty() isActive: boolean;
  @ApiProperty() lastLoginAt: string;
  @ApiProperty({ nullable: true }) otpRequestWindowStart: string | null;
  @ApiProperty() createdAt: string;
  @ApiProperty() updatedAt: string;
}

class SessionDto {
  @ApiProperty() _id: string;
  @ApiProperty() userId: string;
  @ApiProperty() ipAddress: string;
  @ApiProperty() userAgent: string;
  @ApiProperty() deviceName: string;
  @ApiProperty() isCurrentDevice: boolean;
  @ApiProperty() isSuspicious: boolean;
  @ApiProperty() revoked: boolean;
  @ApiProperty() lastSeenAt: string;
  @ApiProperty() createdAt: string;
  @ApiProperty() updatedAt: string;
  @ApiProperty() __v: number;
}

class TokenDto {
  @ApiProperty() sub: string;
  @ApiProperty() type: string;
  @ApiProperty() sessionId: string;
  @ApiProperty() iat: number;
  @ApiProperty() exp: number;
}

class MeDataDto {
  @ApiProperty({ type: UserDto }) user: UserDto;
  @ApiProperty({ type: SessionDto }) session: SessionDto;
  @ApiProperty({ type: TokenDto }) token: TokenDto;
}

export class MeResponseDto {
  @ApiProperty() status: number;
  @ApiProperty({ type: MeDataDto }) data: MeDataDto;
}
