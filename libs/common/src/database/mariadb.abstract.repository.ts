import { Logger, NotFoundException } from '@nestjs/common';
import {
  Repository,
  DeepPartial,
  SaveOptions,
  FindOneOptions,
  FindManyOptions,
  DeleteResult,
  FindOptionsWhere,
  ObjectLiteral,
} from 'typeorm';

export abstract class MariadbAbstractRepository<TEntity extends ObjectLiteral> {
  protected abstract readonly logger: Logger;

  constructor(protected readonly repository: Repository<TEntity>) {}

  async create(
    entity: DeepPartial<TEntity>,
    options?: SaveOptions,
  ): Promise<TEntity> {
    try {
      const createdEntity = this.repository.create(entity);

      return await this.repository.save(createdEntity, options);
    } catch (error) {
      throw error;
    }
  }

  async insertMany(
    entity: DeepPartial<TEntity[]>,
    options?: SaveOptions,
  ): Promise<TEntity[]> {
    try {
      const createdEntity = this.repository.create(entity);

      return await this.repository.save(createdEntity, options);
    } catch (error) {
      throw new NotFoundException(error);
    }
  }

  async findOne(conditions: FindOneOptions<TEntity>): Promise<TEntity> {
    try {
      const entity = await this.repository.findOne(conditions);

      if (!entity) {
        this.logger.warn('Entity not found', conditions);
        throw new NotFoundException('Entity not found!');
      }

      return entity;
    } catch (error) {
      this.logger.warn('Error finding entity', conditions);

      throw new NotFoundException(error);
    }
  }

  async find(options?: FindManyOptions<TEntity>): Promise<TEntity[]> {
    try {
      return await this.repository.find(options);
    } catch (error) {
      throw new NotFoundException(error);
    }
  }

  async save(
    entity: DeepPartial<TEntity> | DeepPartial<TEntity[]>,
    options?: SaveOptions,
  ): Promise<TEntity | TEntity[]> {
    try {
      // Log the entity before saving
      this.logger.log('Saving entity:', entity);

      // Check if entity is an array or a single object
      if (Array.isArray(entity)) {
        // Handle array of entities
        const savedEntities = await this.repository.save(entity as DeepPartial<TEntity>[], options);
        this.logger.log('Saved entities:', savedEntities);
        return savedEntities;
      } else {
        // Handle single entity
        const savedEntity = await this.repository.save(entity as DeepPartial<TEntity>, options);
        this.logger.log('Saved entity:', savedEntity);
        return savedEntity;
      }
    } catch (error) {
      // Log the error message
      this.logger.error('Error saving entity:', error.message);
      // Rethrow the error for higher-level handling
      throw error;
    }
  }

  async update(
    conditions: Partial<TEntity>,
    updateData: DeepPartial<TEntity>,
    options?: SaveOptions,
  ): Promise<TEntity> {
    try {      
      // Find the entity based on the provided conditions
      const entity = await this.repository.findOne({
        where: conditions as FindOptionsWhere<TEntity>,
      });

      console.log(entity);
  
      if (!entity) {
        this.logger.warn('Entity not found for update', conditions);
        throw new NotFoundException('Entity not found for update');
      }
  
      // Merge the existing entity with the update data
      const updatedEntity = this.repository.merge(entity, updateData);
  
      // Save the updated entity
      return await this.repository.save(updatedEntity, options);
    } catch (error) {
      this.logger.warn('Error updating entity', { conditions, updateData });
      throw error;
    }
  }
  
  async findOneAndDelete(
    conditions: FindOneOptions<TEntity>,
  ): Promise<DeleteResult> {
    try {
      const entity: any = await this.findOne(conditions);

      if (!entity) {
        this.logger.warn('Entity not found for deletion', conditions);
        throw new NotFoundException('Entity not found for deletion');
      }

      return await this.repository.delete(entity?.id);
    } catch (error) {
      this.logger.warn('Error deleting entity', conditions);

      throw new NotFoundException(error);
    }
  }
}
