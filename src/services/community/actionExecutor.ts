import { getDb } from '../../db/connection.js'
import type { CommunityAction } from '../../types/index.js'
import { getCommunity, updateCommunityFromPayload } from '../communityService.js'
import { addAdmin, removeAdmin } from '../communityAdminService.js'
import {
  syncCommunitySettingsToRepo,
  syncCommunityManifestoToRepo,
  syncCommunityRulesetToRepo,
  publishCommunityBlogPost,
} from './repoSyncService.js'
import { nowIso } from '../../utils/time.js'

export async function executeApprovedAction(action: CommunityAction): Promise<boolean> {
  const db = getDb()
  const now = nowIso()

  try {
    // 1. Apply local changes
    switch (action.actionType) {
      case 'name_change':
      case 'compass_change':
      case 'manifesto_update':
      case 'ruleset_mod': {
        updateCommunityFromPayload(action.communityId, action.payload)
        break
      }
      case 'admin_add': {
        addAdmin(action.communityId, action.payload.adminDid as string, action.proposedByDid)
        break
      }
      case 'admin_remove': {
        removeAdmin(action.communityId, action.payload.adminDid as string, action.proposedByDid)
        break
      }
      case 'blog_post': {
        // Local state already captured in action payload; PDS sync below
        break
      }
    }

    // 2. Sync to ATProto repo (best-effort)
    let syncError: string | null = null
    try {
      await syncActionToPdsRepo(action)
    } catch (pdsErr) {
      syncError = pdsErr instanceof Error ? pdsErr.message : String(pdsErr)
      // Don't fail the action just because PDS sync failed
    }

    db.prepare(
      'UPDATE community_actions SET status = ?, executed_at = ?, failed_reason = ? WHERE id = ?'
    ).run('executed', now, syncError, action.id)
    return true
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err)
    db.prepare(
      'UPDATE community_actions SET status = ?, failed_reason = ? WHERE id = ?'
    ).run('failed', errorMessage, action.id)
    return false
  }
}

async function syncActionToPdsRepo(action: CommunityAction): Promise<void> {
  const community = getCommunity(action.communityId)
  if (!community) return
  if (!community.pdsHost) return // No PDS configured, skip

  switch (action.actionType) {
    case 'name_change':
    case 'compass_change': {
      await syncCommunitySettingsToRepo(action.communityId)
      break
    }
    case 'manifesto_update': {
      const text = (action.payload.text as string) || ''
      await syncCommunityManifestoToRepo(action.communityId, text)
      break
    }
    case 'ruleset_mod': {
      const text = (action.payload.text as string) || ''
      await syncCommunityRulesetToRepo(action.communityId, text)
      break
    }
    case 'blog_post': {
      const title = (action.payload.title as string) || ''
      const content = (action.payload.content as string) || ''
      await publishCommunityBlogPost(action.communityId, title, content, action.proposedByDid)
      break
    }
    // admin_add and admin_remove don't need PDS sync for the action itself
    // (the member record is written when membership is approved)
  }
}
