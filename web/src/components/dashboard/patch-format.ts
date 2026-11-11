import type { PatchState } from '@/types/api'

export const PATCH_STATE_LABEL: Record<PatchState, string> = {
  proposed: 'Proposed',
  applied: 'Applied',
  rolled_back: 'Rolled back',
}
