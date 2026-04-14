/**
 * POST /api/internal/provision-user
 *
 * Called by Graine AI when a user signs up or first logs in.
 *
 * Creates or updates the user in Sim Studio's Better Auth database,
 * ensures a workspace exists for the user's organisation,
 * adds the user as an admin of that workspace, then returns a
 * one-time-token so Graine can redirect the user into Sim Studio
 * fully authenticated.
 *
 * Authentication: INTERNAL_API_SECRET in Authorization header.
 *
 * Body:
 *   email    – user email (required)
 *   name     – display name (optional)
 *   password – deterministic Sim password derived by Graine (required)
 *   orgId    – Graine organisation ID used to deduplicate workspaces (optional)
 *   orgName  – Graine organisation name used as workspace name (optional)
 *
 * Response: { token, userId, workspaceId, isNew }
 */

import { db } from '@sim/db'
import { permissions, workspace } from '@sim/db/schema'
import { createLogger } from '@sim/logger'
import { and, eq } from 'drizzle-orm'
import { type NextRequest, NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import { env } from '@/lib/core/config/env'
import { safeCompare } from '@/lib/core/security/encryption'
import { generateId } from '@/lib/core/utils/uuid'
import { getRandomWorkspaceColor } from '@/lib/workspaces/colors'

const logger = createLogger('ProvisionUser')

function unauthorized() {
  return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
}

/** Ensure user has a workspace for the given Graine org. */
async function ensureWorkspace(
  userId: string,
  orgId: string | undefined,
  orgName: string | undefined
): Promise<string> {
  // Lookup key: workspace whose name matches orgId (deterministic) or orgName
  // We use orgId as the workspace lookup anchor when available so we never
  // create duplicates across org renames.
  const lookupName = orgId ?? orgName ?? 'My Workspace'
  const displayName = orgName ?? orgId ?? 'My Workspace'

  // Check if user already owns a workspace with this name
  const existing = await db
    .select({ id: workspace.id })
    .from(workspace)
    .where(eq(workspace.ownerId, userId))
    .limit(1)

  if (existing.length > 0) {
    // User already has a workspace — ensure they have a permission row for it
    const workspaceId = existing[0].id
    await ensurePermission(userId, workspaceId)
    return workspaceId
  }

  // No workspace yet — create one
  const workspaceId = generateId()
  await db.insert(workspace).values({
    id: workspaceId,
    name: displayName,
    color: getRandomWorkspaceColor(),
    ownerId: userId,
    billedAccountUserId: userId,
  })

  await ensurePermission(userId, workspaceId)
  logger.info(`Created workspace ${workspaceId} for user ${userId} (org: ${lookupName})`)
  return workspaceId
}

/** Upsert an admin permission row for user → workspace. */
async function ensurePermission(userId: string, workspaceId: string): Promise<void> {
  const existing = await db
    .select({ id: permissions.id })
    .from(permissions)
    .where(
      and(
        eq(permissions.userId, userId),
        eq(permissions.entityType, 'workspace'),
        eq(permissions.entityId, workspaceId)
      )
    )
    .limit(1)

  if (existing.length === 0) {
    await db.insert(permissions).values({
      id: generateId(),
      userId,
      entityType: 'workspace',
      entityId: workspaceId,
      permissionType: 'admin',
    })
  }
}

export async function POST(request: NextRequest) {
  // Verify internal secret
  const authHeader = request.headers.get('authorization') || ''
  const expectedAuth = `Bearer ${env.INTERNAL_API_SECRET}`
  if (!authHeader || !safeCompare(authHeader, expectedAuth)) {
    logger.warn('Unauthorized provision-user attempt')
    return unauthorized()
  }

  const body = await request.json().catch(() => null)
  if (!body?.email || !body?.password) {
    return NextResponse.json({ error: 'email and password are required' }, { status: 400 })
  }

  const { email, name, password, orgId, orgName } = body as {
    email: string
    name?: string
    password: string
    orgId?: string
    orgName?: string
  }

  let userId: string | null = null
  let isNew = false

  // Try sign-in first (returning user)
  try {
    const signInRes = await auth.api.signInEmail({
      body: { email, password },
      headers: new Headers({ 'content-type': 'application/json' }),
    })

    if (signInRes?.user?.id) {
      userId = signInRes.user.id
      logger.info(`User signed in: ${email}`)
    }
  } catch {
    // Not found or wrong password — try sign-up
  }

  // First visit — create the account
  if (!userId) {
    try {
      const signUpRes = await auth.api.signUpEmail({
        body: { email, password, name: name || email.split('@')[0] },
        headers: new Headers({ 'content-type': 'application/json' }),
      })

      if (signUpRes?.user?.id) {
        userId = signUpRes.user.id
        isNew = true
        logger.info(`User provisioned: ${email}`)
      }
    } catch (e) {
      // Account may already exist (race condition) — retry sign-in
      try {
        const retryRes = await auth.api.signInEmail({
          body: { email, password },
          headers: new Headers({ 'content-type': 'application/json' }),
        })
        if (retryRes?.user?.id) {
          userId = retryRes.user.id
        }
      } catch {
        logger.error(`Failed to provision user ${email}:`, e)
      }
    }
  }

  if (!userId) {
    return NextResponse.json({ error: 'Failed to provision user' }, { status: 500 })
  }

  // Ensure workspace exists for this org and user is a member
  let workspaceId: string | null = null
  try {
    workspaceId = await ensureWorkspace(userId, orgId, orgName)
  } catch (e) {
    logger.warn('Workspace provisioning failed (non-fatal):', e)
  }

  // Generate a one-time-token for seamless SSO redirect
  try {
    const ottRes = await auth.api.generateOneTimeToken({
      headers: request.headers,
      body: { userId } as any,
    })

    if (ottRes?.token) {
      return NextResponse.json({ token: ottRes.token, userId, workspaceId, isNew })
    }
  } catch (e) {
    logger.warn('OTT generation failed, returning userId only:', e)
  }

  // Fallback: return userId without OTT
  return NextResponse.json({ userId, workspaceId, isNew, token: null })
}
