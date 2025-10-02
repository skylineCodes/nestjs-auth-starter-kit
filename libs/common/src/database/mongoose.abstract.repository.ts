import mongoose, { FilterQuery, Model, Types, UpdateQuery } from "mongoose";
import { AbstractDocument } from "./abstract.schema";
import { Logger, NotFoundException } from "@nestjs/common";

export abstract class MongooseAbstractRepository<TDocument extends AbstractDocument> {
  protected abstract readonly logger: Logger;

  constructor(protected readonly model: Model<TDocument>) {}

  async create(document: Omit<TDocument, '_id'>): Promise<TDocument> {
    try {
      const createdDocument = new this.model({
        ...document,
        _id: new Types.ObjectId(),
      });

      return (await createdDocument.save()).toJSON() as unknown as TDocument;
    } catch (error) {
      throw error;      
    }
  }

  async insertMany(documents: Omit<TDocument, '_id'>[]): Promise<TDocument[]> {
    try {
      const createdDocuments = documents.map((doc) => ({
        ...doc,
        _id: new Types.ObjectId(),
      }));

      const result = await this.model.insertMany(createdDocuments);

      return result.map((doc) => doc as unknown as TDocument);
    } catch (error) {
      throw new NotFoundException(error);      
    }
  }

  async updateMany(
    filter: FilterQuery<TDocument>,
    update: UpdateQuery<TDocument>,
    // options?: mongoose.UpdateQuery<TDocument> & mongoose.QueryOptions,
  ): Promise<{ matchedCount: number; modifiedCount: number }> {
    try {
      const result = await this.model.updateMany(filter, update);
  
      return {
        matchedCount: result.matchedCount,
        modifiedCount: result.modifiedCount,
      };
    } catch (error) {
      throw new NotFoundException(error);
    }
  }

  async findOne(filterQuery: FilterQuery<TDocument>): Promise<TDocument | null> {
    try {
      const document = await this.model
        .findOne(filterQuery)
        .lean<TDocument>(true); 

      if (!document) {
        this.logger.warn('Document was not found with filterQuery', filterQuery);
        return null;
      }

      return document;
    } catch (error) {
      this.logger.warn('Document was not found with filterQuery', filterQuery);

      throw error;
    }
  }

  async findOneAndUpdate(
    filterQuery: FilterQuery<TDocument>,
    update: UpdateQuery<TDocument>,
  ): Promise<TDocument> {
    try {
      const document = await this.model.findOneAndUpdate(filterQuery, update, {
          new: true,
        })
        .lean<TDocument>(true);

      if (!document) {
        this.logger.warn('Document was not found with filterQuery', filterQuery);
        throw new NotFoundException('Document not found');
      }

      return document;
    } catch (error) {
      this.logger.warn('Document was not found with filterQuery', filterQuery);

      throw new NotFoundException(error);
    }
  }

  // async find(filterQuery: FilterQuery<TDocument> = {}): Promise<TDocument[]> {
  //   try {
  //     return this.model.find(filterQuery).sort({ createdAt: -1 }).select('-password').lean<TDocument[]>(true);
  //   } catch (error) {
  //     throw new NotFoundException(error);
  //   }
  // }

  async find(
    filterQuery: FilterQuery<TDocument> = {},
    options?: {
      sort?: Record<string, 1 | -1>,
      page?: number,
      pageSize?: number,
      selectOption?: any
    }
  ): Promise<TDocument[]> {
    try {
      const { sort = { createdAt: -1 }, page, pageSize, selectOption } = options ?? {};

      const query = this.model.find(filterQuery);

      // apply sort
      query.sort(sort).select(selectOption);

      // optional select
      // if (select) query.select(select);

      // optional pagination
      if (page && pageSize) {
        const skip = Math.max(0, (page - 1) * pageSize);
        query.skip(skip).limit(pageSize);
      }

      // execute and return plain JS objects
      return await query.lean<TDocument[]>(true).exec();
    } catch (error) {
      throw new NotFoundException(error);
    }
  }

  async paginatedFind(filterQuery: FilterQuery<TDocument> = {}): Promise<TDocument[]> {
    try {
      const { page, pageSize } = filterQuery;

      return this.model.find().skip((page - 1) * pageSize).limit(pageSize).exec();
    } catch (error) {
      throw new NotFoundException(error);
    }
  }

  async countDocuments(filterQuery?: FilterQuery<TDocument>): Promise<number> {
    try {
      return this.model.countDocuments().exec();
    } catch (error) {
      throw new NotFoundException(error);
    }
  }

  async findOneAndDelete(
    filterQuery: FilterQuery<TDocument>,
  ): Promise<TDocument> {
    try {
      const document = await this.model.findOneAndDelete(filterQuery).lean<TDocument>(true);

      if (!document) {
        throw new NotFoundException('Document not found');
      }

      return document;
    } catch (error) {
      throw new NotFoundException(error);
    }
  }
}