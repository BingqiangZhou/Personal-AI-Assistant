/**
 * TanStack Query hooks — re-exports from api.ts
 *
 * All query and mutation hooks are defined in @/lib/api.ts alongside
 * their corresponding API fetcher functions. This file provides a
 * centralized import point for components that prefer importing from
 * a dedicated queries module.
 */

export {
  // Podcast queries
  usePodcasts,
  usePodcast,
  useRankings,
  useTrackPodcast,
  useUntrackPodcast,

  // Episode queries
  useEpisodes,
  useEpisode,
  useTranscribeEpisode,
  useSummarizeEpisode,

  // Transcript & Summary queries
  useTranscript,
  useSummary,

  // Settings queries
  useProviders,
  useCreateProvider,
  useUpdateProvider,
  useDeleteProvider,
  useTestProvider,
  useCreateModel,
  useUpdateModel,
  useDeleteModel,

  // Sync queries
  useSyncRankings,
  useSyncEpisodes,

  // Dashboard queries
  useDashboardStats,
} from './api';
