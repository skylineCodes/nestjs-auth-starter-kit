import { MongooseAbstractRepository } from '@app/common';
import { Injectable, Logger } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { IpLocation } from '../models/ip-location.schema';

@Injectable()
export class IpLocationRepository extends MongooseAbstractRepository<IpLocation> {
  protected readonly logger = new Logger(IpLocationRepository.name);

  constructor(@InjectModel(IpLocation.name) ipLocationModel: Model<IpLocation>) {
    super(ipLocationModel);
  }
}