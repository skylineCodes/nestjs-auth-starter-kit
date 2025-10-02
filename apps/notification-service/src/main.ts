import cookieParser from 'cookie-parser';
import { NestFactory } from '@nestjs/core';
import { NotificationServiceModule } from './notification-service.module';
import { ConfigService } from '@nestjs/config';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { ValidationPipe } from '@nestjs/common';
// import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';

async function bootstrap() {
  const app = await NestFactory.create(NotificationServiceModule, { bufferLogs: true });
  const configService = app.get(ConfigService);
  app.connectMicroservice({
    transport: Transport.TCP,
    options: {
      host: '0.0.0.0',
      port: configService.get('PORT'),
    },
  });

  app.connectMicroservice<MicroserviceOptions>({
    transport: Transport.RMQ,
    options: {
      urls: ['amqp://admin:admin_9202@host.docker.internal:5672'],
      queue: 'notifications_queue_auth_kit',
      queueOptions: {
        durable: false,
      },
    },
  });

  app.use(cookieParser());
  app.useGlobalPipes(new ValidationPipe({ whitelist: true }));

  // Use Winston as the logger
  // app.useLogger(app.get(WINSTON_MODULE_NEST_PROVIDER));

  // app.useLogger(app.get(Logger));
  await app.startAllMicroservices();
}
bootstrap();
