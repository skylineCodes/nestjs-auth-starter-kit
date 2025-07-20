import { MongooseAbstractRepository } from '@app/common';
import { Injectable, Logger } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { LoginActivity } from '../models/login-activity.schema/login-activity.schema';

@Injectable()
export class LoginActivityRepository extends MongooseAbstractRepository<LoginActivity> {
  protected readonly logger = new Logger(LoginActivityRepository.name);

  constructor(@InjectModel(LoginActivity.name) loginActivityModel: Model<LoginActivity>) {
    super(loginActivityModel);
  }
}