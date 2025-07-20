import { DynamicModule, Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ModelDefinition, MongooseModule } from '@nestjs/mongoose';
import { TypeOrmModule } from '@nestjs/typeorm';
// import { OrderItem } from 'apps/order-service/src/models/order-item.schema';
// import { Order } from 'apps/order-service/src/models/order-service.schema';
// import { Wishlist } from 'apps/order-service/src/wishlist/models/wishlist.schema';
import { DataSourceOptions } from 'typeorm';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),

    // MongoDB configuration
    MongooseModule.forRootAsync({
      useFactory: (configService: ConfigService) => ({
        uri: configService.get('MONGODB_URI'),
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [ConfigService],
})

export class DatabaseModule {
  static forFeature(models: ModelDefinition[]): DynamicModule {
    return MongooseModule.forFeature(models);
  }

  static forTypeOrmFeature(
    entities: any[],
    connectionName?: string,
  ): DynamicModule {
    return TypeOrmModule.forFeature(entities, connectionName);
  }

  static forTypeOrmRoot(
    options?: DataSourceOptions,
    connectionName?: string,
  ): DynamicModule {
    return TypeOrmModule.forRootAsync({
      name: connectionName,
      useFactory: (configService: ConfigService) => ({
        type: 'mariadb',
        host: configService.get('MARIADB_HOST'),
        port: configService.get('MARIADB_PORT'),
        username: configService.get('MARIADB_USER'),
        password: configService.get('MARIADB_PASSWORD'),
        database: configService.get('MARIADB_DB'),
        // entities: [Wishlist, Order, OrderItem],
        // entities: options?.entities || [__dirname + '/../**/*.schema{.ts,.js}'],
        synchronize: true,
      }),
      inject: [ConfigService],
    });
  }
}
