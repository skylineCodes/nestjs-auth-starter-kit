import { MongooseAbstractRepository } from '@app/common';
import { Injectable, Logger } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { Session } from '../models/session.schema';

@Injectable()
export class SessionRepository extends MongooseAbstractRepository<Session> {
  protected readonly logger = new Logger(SessionRepository.name);

  constructor(@InjectModel(Session.name) sessionModel: Model<Session>) {
    super(sessionModel);
  }
}