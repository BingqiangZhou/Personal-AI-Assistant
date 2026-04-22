'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  Podcast,
  Settings,
  Radio,
} from 'lucide-react';
import { cn } from '@/lib/utils';

const navItems = [
  {
    label: '仪表盘',
    href: '/',
    icon: LayoutDashboard,
  },
  {
    label: '播客',
    href: '/podcasts',
    icon: Podcast,
  },
  {
    label: '设置',
    href: '/settings',
    icon: Settings,
  },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="flex h-screen w-60 flex-col border-r bg-sidebar-background text-sidebar-foreground">
      {/* Logo / Branding */}
      <div className="flex h-14 items-center gap-2 border-b px-4">
        <Radio className="h-6 w-6 text-sidebar-primary" />
        <span className="text-lg font-bold tracking-tight">PodDigest</span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 px-3 py-4">
        {navItems.map((item) => {
          const isActive =
            item.href === '/'
              ? pathname === '/'
              : pathname.startsWith(item.href);

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                'flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
                isActive
                  ? 'bg-sidebar-accent text-sidebar-accent-foreground'
                  : 'text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground'
              )}
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="border-t px-4 py-3">
        <p className="text-xs text-muted-foreground">
          PodDigest v1.0
        </p>
      </div>
    </aside>
  );
}
