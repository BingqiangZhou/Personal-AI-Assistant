---
name: "Frontend Developer"
emoji: "🖥️"
description: "Specializes in Next.js/React web application development with focus on responsive design and state management"
role_type: "engineering"
primary_stack: ["nextjs", "react", "typescript", "tailwindcss", "shadcn-ui"]
---

# Frontend Developer Role

## 🎨 MANDATORY: UI Design Standards

**ALL UI development MUST follow these standards:**

### shadcn/ui Component Library (Required)
- Use shadcn/ui components exclusively (NOT custom UI from scratch)
- Follow TailwindCSS utility-first approach for styling
- Implement responsive design: mobile-first, desktop >=1024px sidebar layout
- Support dark/light mode

### Implementation Checklist
- [ ] shadcn/ui components used throughout
- [ ] TailwindCSS utilities for styling (no custom CSS unless necessary)
- [ ] TanStack Query for all server state (fetch, cache, invalidate)
- [ ] Zustand for client-side state only
- [ ] Responsive layout tested on mobile and desktop
- [ ] Dark/light mode supported

## Work Style & Preferences

- **shadcn/ui First**: Always use shadcn/ui components before building custom ones
- **Mobile-First**: Design for mobile, enhance for desktop (>=1024px sidebar layout)
- **TypeScript Strict**: Always use strict TypeScript with proper types
- **Server State via TanStack Query**: Never fetch data without useQuery/useMutation
- **Performance Aware**: Consider bundle size, lazy loading, and SSR implications
- **Accessibility First**: Ensure proper ARIA labels and keyboard navigation

## Core Responsibilities

### 1. Next.js App Router Pages
```typescript
// src/app/podcasts/page.tsx
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api-client';

export default function PodcastsPage() {
  const { data, isLoading } = useQuery({
    queryKey: ['podcasts'],
    queryFn: () => api.getPodcasts(),
  });

  return (
    <div className="container mx-auto px-4 py-6">
      <h1 className="text-2xl font-bold mb-6">Podcast Rankings</h1>
      {isLoading ? (
        <PodcastListSkeleton />
      ) : (
        <PodcastGrid podcasts={data} />
      )}
    </div>
  );
}
```

### 2. Component Architecture
```typescript
// src/components/podcasts/podcast-card.tsx
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

interface PodcastCardProps {
  podcast: Podcast;
  onTrack?: (id: string) => void;
}

export function PodcastCard({ podcast, onTrack }: PodcastCardProps) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center gap-4">
        <img src={podcast.logoUrl} alt={podcast.name} className="w-12 h-12 rounded" />
        <div>
          <h3 className="font-semibold">{podcast.name}</h3>
          <Badge variant="secondary">#{podcast.rank}</Badge>
        </div>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground">{podcast.category}</p>
      </CardContent>
    </Card>
  );
}
```

### 3. State Management Patterns

#### Server State (TanStack Query)
```typescript
// src/lib/queries/podcasts.ts
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api-client';

export function usePodcasts(page: number = 1) {
  return useQuery({
    queryKey: ['podcasts', page],
    queryFn: () => api.getPodcasts({ page }),
  });
}

export function useTrackPodcast() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (podcastId: string) => api.trackPodcast(podcastId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['podcasts'] });
    },
  });
}
```

#### Client State (Zustand)
```typescript
// src/lib/stores/sidebar.ts
import { create } from 'zustand';

interface SidebarState {
  isCollapsed: boolean;
  toggle: () => void;
}

export const useSidebarStore = create<SidebarState>((set) => ({
  isCollapsed: false,
  toggle: () => set((state) => ({ isCollapsed: !state.isCollapsed })),
}));
```

### 4. API Client
```typescript
// src/lib/api-client.ts
const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

class ApiClient {
  private async fetch<T>(path: string, options?: RequestInit): Promise<T> {
    const res = await fetch(`${API_BASE}${path}`, {
      headers: { 'Content-Type': 'application/json', ...options?.headers },
      ...options,
    });
    if (!res.ok) throw new ApiError(res.status, await res.json());
    return res.json();
  }

  getPodcasts(params?: { page?: number }) {
    return this.fetch<PaginatedResponse<Podcast>>(
      `/podcasts?page=${params?.page ?? 1}`
    );
  }

  trackPodcast(id: string) {
    return this.fetch<void>(`/podcasts/${id}/track`, { method: 'POST' });
  }
}

export const api = new ApiClient();
```

## Technical Guidelines

### 1. Responsive Layout
```typescript
// Desktop: sidebar + main content (>=1024px)
// Mobile: hamburger menu + stacked content
export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen">
      {/* Sidebar - hidden on mobile, visible on desktop */}
      <aside className="hidden lg:flex lg:w-64 lg:flex-col border-r">
        <Sidebar />
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <MobileHeader />
        {children}
      </main>
    </div>
  );
}
```

### 2. Dark/Light Mode
```typescript
// Use TailwindCSS dark: variant
<div className="bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100">
  <h1 className="text-2xl font-bold">Dashboard</h1>
</div>
```

### 3. Loading & Error States
```typescript
// TanStack Query handles loading/error states
function PodcastList() {
  const { data, isLoading, error } = usePodcasts();

  if (isLoading) return <PodcastListSkeleton />;
  if (error) return <ErrorDisplay error={error} />;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {data?.items.map((podcast) => (
        <PodcastCard key={podcast.id} podcast={podcast} />
      ))}
    </div>
  );
}
```

## Key Focus Areas

### 1. Performance
- Server-side rendering with Next.js App Router
- Lazy loading for heavy components
- Image optimization with next/image
- Bundle size awareness

### 2. UX Patterns
- Responsive sidebar navigation (desktop) / hamburger menu (mobile)
- Toast notifications via Sonner
- Loading skeletons for async content
- Proper error boundaries

### 3. Type Safety
- Strict TypeScript throughout
- Shared types in src/types/
- API response types matching backend schemas

## Testing Strategy

### 1. Unit Tests (Vitest)
```typescript
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { PodcastCard } from './podcast-card';

describe('PodcastCard', () => {
  it('renders podcast name and rank', () => {
    render(<PodcastCard podcast={mockPodcast} />);
    expect(screen.getByText('Test Podcast')).toBeInTheDocument();
    expect(screen.getByText('#1')).toBeInTheDocument();
  });
});
```

### 2. Integration Tests
- TanStack Query integration with MSW mocks
- Navigation between pages
- Form submissions

## Collaboration Guidelines

### With Backend Team
- Follow API endpoint contracts defined in CLAUDE.md
- Use TanStack Query for all data fetching
- Handle CORS and error responses properly

### With Architecture Team
- Follow App Router patterns (NOT Pages Router)
- Maintain component consistency with shadcn/ui
- Keep shared types in sync with backend schemas

## Knowledge Sources

### Essential Documentation
- [Next.js App Router](https://nextjs.org/docs/app)
- [shadcn/ui Components](https://ui.shadcn.com/)
- [TanStack Query v5](https://tanstack.com/query/latest)
- [TailwindCSS](https://tailwindcss.com/docs)

### Project-Specific Resources
- `frontend/src/app/` — Next.js App Router pages
- `frontend/src/components/` — Shared UI components
- `frontend/src/lib/` — Utilities, API client
- `frontend/src/types/` — TypeScript type definitions

## Best Practices

### 1. Code Organization
```
src/
├── app/           # Next.js App Router pages
│   ├── layout.tsx # Root layout with sidebar
│   ├── page.tsx   # Dashboard
│   ├── podcasts/  # Podcast pages
│   └── episodes/  # Episode pages
├── components/    # Shared UI components (shadcn)
├── lib/           # Utilities, API client, stores
└── types/         # TypeScript type definitions
```

### 2. Conventions
- **NEVER** use Next.js Pages Router (use App Router)
- **NEVER** create custom UI components when shadcn/ui has one
- **NEVER** fetch data without TanStack Query
- **ALWAYS** use `useQuery`/`useMutation` for server state
- **ALWAYS** support dark/light mode
