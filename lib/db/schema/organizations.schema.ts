import { pgTable, varchar, text, timestamp, boolean, uuid, jsonb, pgEnum } from 'drizzle-orm/pg-core';

export const organizations = pgTable('organizations', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 255 }).notNull(),
  slug: varchar('slug', { length: 100 }).notNull().unique(),
  logoUrl: text('logo_url'),
  settings: jsonb('settings').$type<OrgSettings>().default({}),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

export type Organization = typeof organizations.$inferSelect;
export type NewOrganization = typeof organizations.$inferInsert;

export const permissionsEnum = pgEnum('permissions', [
  'org:manage',
  'org:invite', 
  'org:roles',
  'chat:create',
  'chat:share',
  'chat:delete',
  'settings:manage'
]);

export const userOrganizations = pgTable('user_organizations', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: varchar('user_id', { length: 255 }).notNull(),
  organizationId: uuid('organization_id').notNull().references(() => organizations.id),
  role: varchar('role', { length: 50 }).notNull().default('member'),
  invitedBy: varchar('invited_by', { length: 255 }),
  joinedAt: timestamp('joined_at').defaultNow(),
}, {
  unique: {
    name: 'user_organizations_user_org_unique',
    columns: ['userId', 'organizationId'],
  },
});

export type UserOrganization = typeof userOrganizations.$inferSelect;
export type NewUserOrganization = typeof userOrganizations.$inferInsert;

export const organizationPermissions = pgTable('organization_permissions', {
  id: uuid('id').primaryKey().defaultRandom(),
  organizationId: uuid('organization_id').notNull().references(() => organizations.id),
  role: varchar('role', { length: 50 }).notNull(),
  permission: permissionsEnum('permission').notNull(),
});

export type OrganizationPermission = typeof organizationPermissions.$inferSelect;

// Type for organization settings
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
    'settings:manage'
  ],
  admin: [
    'org:invite',
    'org:roles',
    'chat:create',
    'chat:share',
    'chat:delete'
  ],
  member: [
    'chat:create',
    'chat:share'
  ],
  guest: [
    'chat:create'
  ]
};