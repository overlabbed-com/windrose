/**
 * Windrose PostgreSQL Schema
 * 
 * Uses Drizzle ORM with pgTable, uuid, varchar, text, timestamp, jsonb.
 * 
 * Note: Using a factory pattern to avoid build-time execution issues.
 */

import { pgTable, uuid, varchar, text, timestamp, jsonb } from 'drizzle-orm/pg-core';

// =============================================================================
// Enum values (as TypeScript constants)
// =============================================================================

export type Permission = 'org:manage' | 'org:invite' | 'org:roles' | 'chat:create' | 'chat:share' | 'chat:delete' | 'settings:manage';
export type UserOrgRole = 'owner' | 'admin' | 'member' | 'guest';
export type MessageRole = 'user' | 'assistant' | 'system';

// =============================================================================
// Users
// =============================================================================

export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  email: varchar('email', { length: 255 }).notNull().unique(),
  passwordHash: varchar('password_hash', { length: 255 }).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updatedAt').defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;

// =============================================================================
// Sessions
// =============================================================================

export const sessions = pgTable('sessions', {
  tokenHash: varchar('token_hash', { length: 64 }).notNull().unique(),
  userId: uuid('user_id').notNull(),
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

export type Session = typeof sessions.$inferSelect;
export type NewSession = typeof sessions.$inferInsert;

// =============================================================================
// Organizations
// =============================================================================

export const organizations = pgTable('organizations', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 255 }).notNull(),
  slug: varchar('slug', { length: 100 }).notNull().unique(),
  logoUrl: text('logo_url'),
  settings: jsonb('settings').default({}),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

export type Organization = typeof organizations.$inferSelect;
export type NewOrganization = typeof organizations.$inferInsert;

// =============================================================================
// User Organizations (Membership)
// =============================================================================

export const userOrganizations = pgTable('user_organizations', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull(),
  organizationId: uuid('organization_id').notNull(),
  role: varchar('role', { length: 50 }).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

export type UserOrganization = typeof userOrganizations.$inferSelect;
export type NewUserOrganization = typeof userOrganizations.$inferInsert;

// =============================================================================
// Organization Permissions
// =============================================================================

export const organizationPermissions = pgTable('organization_permissions', {
  id: uuid('id').primaryKey().defaultRandom(),
  organizationId: uuid('organization_id').notNull(),
  role: varchar('role', { length: 50 }).notNull(),
  permission: varchar('permission', { length: 100 }).notNull(),
  grantedAt: timestamp('granted_at').defaultNow().notNull(),
});

export type OrganizationPermission = typeof organizationPermissions.$inferSelect;
export type NewOrganizationPermission = typeof organizationPermissions.$inferInsert;

// =============================================================================
// API Keys
// =============================================================================

export const apiKeys = pgTable('api_keys', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull(),
  keyHash: varchar('key_hash', { length: 255 }).notNull().unique(),
  name: varchar('name', { length: 255 }).notNull(),
  lastUsedAt: timestamp('last_used_at'),
  expiresAt: timestamp('expires_at'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

export type ApiKey = typeof apiKeys.$inferSelect;
export type NewApiKey = typeof apiKeys.$inferInsert;

// =============================================================================
// Chats
// =============================================================================

export const chats = pgTable('chats', {
  id: uuid('id').primaryKey().defaultRandom(),
  title: varchar('title', { length: 255 }).notNull(),
  userId: varchar('user_id', { length: 255 }).notNull(),
  organizationId: uuid('organization_id'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

export type Chat = typeof chats.$inferSelect;
export type NewChat = typeof chats.$inferInsert;

// =============================================================================
// Messages
// =============================================================================

export const messages = pgTable('messages', {
  id: uuid('id').primaryKey().defaultRandom(),
  chatId: uuid('chat_id').notNull(),
  role: varchar('role', { length: 50 }).notNull(),
  content: text('content').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

export type Message = typeof messages.$inferSelect;
export type NewMessage = typeof messages.$inferInsert;
