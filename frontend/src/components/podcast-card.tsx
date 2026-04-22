'use client';

import Link from 'next/link';
import Image from 'next/image';
import { Star, StarOff } from 'lucide-react';
import {
  Card,
  CardContent,
  CardFooter,
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import type { Podcast } from '@/types';

interface PodcastCardProps {
  podcast: Podcast;
  onTrackToggle?: (id: string, isTracked: boolean) => void;
  isToggling?: boolean;
}

export function PodcastCard({
  podcast,
  onTrackToggle,
  isToggling,
}: PodcastCardProps) {
  return (
    <Card className="group flex flex-col overflow-hidden transition-shadow hover:shadow-lg">
      <Link href={`/podcasts/${podcast.id}`} className="block">
        <CardContent className="p-4">
          <div className="flex items-start gap-3">
            {/* Logo */}
            <div className="relative h-16 w-16 flex-shrink-0 overflow-hidden rounded-lg bg-muted">
              {podcast.logo_url ? (
                <Image
                  src={podcast.logo_url}
                  alt={podcast.name}
                  fill
                  className="object-cover"
                  sizes="64px"
                />
              ) : (
                <div className="flex h-full w-full items-center justify-center text-2xl font-bold text-muted-foreground">
                  {podcast.name.charAt(0)}
                </div>
              )}
            </div>

            {/* Info */}
            <div className="min-w-0 flex-1">
              <h3 className="truncate text-sm font-semibold group-hover:text-primary">
                {podcast.name}
              </h3>
              {podcast.author && (
                <p className="truncate text-xs text-muted-foreground">
                  {podcast.author}
                </p>
              )}
              <div className="mt-1 flex items-center gap-2">
                <Badge variant="secondary" className="text-xs">
                  #{podcast.rank}
                </Badge>
                {podcast.category && (
                  <span className="text-xs text-muted-foreground">
                    {podcast.category}
                  </span>
                )}
              </div>
            </div>
          </div>
        </CardContent>
      </Link>

      <CardFooter className="border-t px-4 py-2">
        <Button
          variant={podcast.is_tracked ? 'secondary' : 'outline'}
          size="sm"
          className="w-full"
          onClick={() => onTrackToggle?.(podcast.id, podcast.is_tracked)}
          disabled={isToggling}
        >
          {podcast.is_tracked ? (
            <>
              <StarOff className="mr-1 h-3.5 w-3.5" />
              取消追踪
            </>
          ) : (
            <>
              <Star className="mr-1 h-3.5 w-3.5" />
              追踪
            </>
          )}
        </Button>
      </CardFooter>
    </Card>
  );
}
