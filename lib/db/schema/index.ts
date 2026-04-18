/**
 * Windrose PostgreSQL Schema
 * 
 * Uses Drizzle ORM with pgTable, uuid, varchar, text, timestamp, jsonb, pgEnum.
 * 
 * Tables:
 * - users: User accounts with password authentication
 * - sessions: Session tokens for session-based auth
 * - organizations: Multi-tenant organization support
 * - user_organizations: User-organization membership with roles
 * - organization_permissions: Role-based permissions per organization
 * - api_keys: API keys for programmatic access
 */

import { pgTable, uuid, varchar, text, timestamp, jsonb, pgEnum } from 'drizzle-orm/pg-core';

// =============================================================================
// Enums
// =============================================================================

export const permissionsEnum = pgEnum('permissions', [
  'org:manage',
  'org:invite',
  'org:roles',
  'chat:create',
  'chat:share',
  'chat:delete',
  'settings:manage',
]);

export const userOrgRoleEnum = pgEnum('user_org_role', [
  'owner',
  'admin',
  'member',
  'guest',
]);

// =============================================================================
// Users
// =============================================================================

export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  email: varchar('email', { length: 255 }).notNull().unique(),
  passwordHash: varchar('password_hash', { length: 255 }).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;

// =============================================================================
// Sessions
// =============================================================================

export const sessions = pgTable('sessions', {
  tokenHash: varchar('token_hash', { length: 64 }).notNull().unique(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
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
  settings: jsonb('settings').$type<OrgSettings>().default({}),
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
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  organizationId: uuid('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  role: userOrgRoleEnum('role').notNull().default('member'),
  joinedAt: timestamp('joined_at').defaultNow().notNull(),
}, {
  unique: {
    name: 'user_organizations_user_org_unique',
    columns: ['userId', 'organizationId'],
  },
});

export type UserOrganization = typeof userOrganizations.$inferSelect;
export type NewUserOrganization = typeof userOrganizations.$inferInsert;

// =============================================================================
// Organization Permissions
// =============================================================================

export const organizationPermissions = pgTable('organization_permissions', {
  id: uuid('id').primaryKey().defaultRandom(),
  organizationId: uuid('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  role: varchar('role', { length: 50 }).notNull(),
  permission: permissionsEnum('permission').notNull(),
});

export type OrganizationPermission = typeof organizationPermissions.$inferSelect;
export type NewOrganizationPermission = typeof organizationPermissions.$inferInsert;

// =============================================================================
// API Keys
// =============================================================================

export const apiKeys = pgTable('api_keys', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  organizationId: uuid('organization_id').references(() => organizations.id, { onDelete: 'set null' }),
  prefix: varchar('prefix', { length: 16 }).notNull(),
  hash: varchar('hash', { length: 255 }).notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  lastUsedAt: timestamp('last_used_at'),
});

export type ApiKey = typeof apiKeys.$inferSelect;
export type NewApiKey = typeof apiKeys.$inferInsert;

// =============================================================================
// Types
// =============================================================================

export interface OrgSettings {
  defaultModel?: string;
  allowedModels?: string[];
  features?: {
    chat?: boolean;
    search?: boolean;
    files?: boolean;
  };
  restrictions?: {
    maxChatsPerDay?: number;
    maxStorageMb?: number;
  };
}

// Default role permissions mapping
export const DEFAULT_ROLE_PERMISSIONS: Record<string, string[]> = {
  owner: [
    'org:manage',
    'org:invite',
    'org:roles',
    'chat:create',
    'chat:share',
    'chat:delete',
    'settings:manage',
  ],
  admin: [
    'org:invite',
    'org:roles',
    'chat:create',
    'chat:share',
    'chat:delete',
  ],
  member: [
    'chat:create',
    'chat:share',
  ],
  guest: [
    'chat:create',
  ],
};