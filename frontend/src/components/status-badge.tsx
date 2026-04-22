'use client';

import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

type Status = 'pending' | 'processing' | 'completed' | 'failed';

interface StatusBadgeProps {
  status: Status | null | undefined;
  type?: 'transcript' | 'summary';
}

const statusConfig: Record<
  Status,
  { label: string; className: string }
> = {
  pending: {
    label: '等待中',
    className: 'bg-yellow-100 text-yellow-800 border-yellow-300 dark:bg-yellow-900/30 dark:text-yellow-400 dark:border-yellow-800',
  },
  processing: {
    label: '处理中',
    className: 'bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-900/30 dark:text-blue-400 dark:border-blue-800',
  },
  completed: {
    label: '已完成',
    className: 'bg-green-100 text-green-800 border-green-300 dark:bg-green-900/30 dark:text-green-400 dark:border-green-800',
  },
  failed: {
    label: '失败',
    className: 'bg-red-100 text-red-800 border-red-300 dark:bg-red-900/30 dark:text-red-400 dark:border-red-800',
  },
};

export function StatusBadge({ status, type }: StatusBadgeProps) {
  if (!status) {
    return (
      <Badge variant="outline" className="text-muted-foreground">
        未开始
      </Badge>
    );
  }

  const config = statusConfig[status];
  const prefix = type === 'transcript' ? '转录' : type === 'summary' ? '总结' : '';

  return (
    <Badge variant="outline" className={cn(config.className)}>
      {prefix}{config.label}
    </Badge>
  );
}
