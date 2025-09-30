import cookieParser from 'cookie-parser';
import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe } from '@nestjs/common';
import { Transport } from '@nestjs/microservices';
import { AuthServiceModule } from './auth-service.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
// import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';

async function bootstrap() {
  const app = await NestFactory.create(AuthServiceModule, { bufferLogs: true });

  const configService: any = app.get(ConfigService);

  app.connectMicroservice({
    transport: Transport.TCP,
    options: {
      host: '0.0.0.0',
      port: configService.get('TCP_PORT'),
    },
  });
   
  app.use(cookieParser());
  app.useGlobalPipes(new ValidationPipe({ whitelist: true }));

  // Get raw Express app
  const expressApp = app.getHttpAdapter().getInstance();

  // Trust proxy (so X-Forwarded-For works)
  expressApp.set('trust proxy', true);

  // Use Winston as the logger
  // app.useLogger(app.get(WINSTON_MODULE_NEST_PROVIDER));

  // Swagger Config
  const config = new DocumentBuilder()
    .setTitle('Auth Kit API')
    .setDescription(
      'Comprehensive API documentation for the Authentication Kit, a modular and extensible authentication solution built with NestJS. ' +
      'This kit provides secure user registration and login, password hashing, session-based authentication with cookies, ' +
      'JWT support, email verification, password reset flows, and refresh token rotation. ' +
      'Designed to be developer-friendly, detailed error handling, and can be easily integrated ' +
      'into existing projects for both monolith and microservice architectures.'
    )
    .setVersion('1.0')
    .addCookieAuth('Authentication')
    .addCookieAuth('refreshToken')
    .build();

  const document = SwaggerModule.createDocument(app, config, {
    ignoreGlobalPrefix: false,
    extraModels: [],
    deepScanRoutes: true,
  });

  document.tags = document.tags?.filter(tag => tag.name !== 'AuthService');

  app.enableCors({
    origin: `http://localhost:${configService.get('PORT')}`,
    credentials: true,
  });

  SwaggerModule.setup('auth-service-docs', app, document, {
    swaggerOptions: {
      withCredentials: true,
    }
  });

  await app.startAllMicroservices();

  await app.listen(configService.get('PORT'));
}
bootstrap();
