'use client';

import { useState } from 'react';
import { Loader2 } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import type { AIProvider, CreateProviderRequest, UpdateProviderRequest } from '@/types';

interface ProviderFormProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  provider?: AIProvider | null;
  onSubmit: (data: CreateProviderRequest | UpdateProviderRequest) => void;
  isSubmitting?: boolean;
}

const PROVIDER_TYPES = [
  { value: 'openai', label: 'OpenAI' },
  { value: 'deepseek', label: 'DeepSeek' },
  { value: 'openrouter', label: 'OpenRouter' },
  { value: 'custom', label: '自定义 (OpenAI 兼容)' },
];

const DEFAULT_URLS: Record<string, string> = {
  openai: 'https://api.openai.com/v1',
  deepseek: 'https://api.deepseek.com/v1',
  openrouter: 'https://openrouter.ai/api/v1',
  custom: '',
};

interface FormValues {
  provider_name: string;
  base_url: string;
  api_key: string;
  is_default: boolean;
}

export function ProviderForm({
  open,
  onOpenChange,
  provider,
  onSubmit,
  isSubmitting,
}: ProviderFormProps) {
  const isEditing = !!provider;

  const [providerType, setProviderType] = useState(
    provider?.provider_name ?? ''
  );

  const defaultValues: FormValues = provider
    ? {
        provider_name: provider.provider_name,
        base_url: provider.base_url,
        api_key: '', // Never pre-fill API key
        is_default: provider.is_default,
      }
    : {
        provider_name: '',
        base_url: '',
        api_key: '',
        is_default: false,
      };

  const [form, setForm] = useState<FormValues>(defaultValues);

  const handleProviderTypeChange = (value: string) => {
    setProviderType(value);
    setForm((prev) => ({
      ...prev,
      provider_name: value,
      base_url: DEFAULT_URLS[value] ?? prev.base_url,
    }));
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (isEditing && provider) {
      const data: UpdateProviderRequest = {};
      if (form.provider_name) data.provider_name = form.provider_name;
      if (form.base_url) data.base_url = form.base_url;
      if (form.api_key) data.api_key = form.api_key;
      data.is_default = form.is_default;
      onSubmit(data);
    } else {
      onSubmit({
        provider_name: form.provider_name,
        base_url: form.base_url,
        api_key: form.api_key,
        is_default: form.is_default,
      });
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[425px]">
        <DialogHeader>
          <DialogTitle>
            {isEditing ? '编辑 AI 提供商' : '添加 AI 提供商'}
          </DialogTitle>
          <DialogDescription>
            {isEditing
              ? '修改 AI 提供商的配置信息'
              : '配置新的 AI 提供商以用于转录和总结'}
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Provider type */}
          <div className="space-y-2">
            <label className="text-sm font-medium">提供商类型</label>
            <Select
              value={providerType}
              onValueChange={handleProviderTypeChange}
            >
              <SelectTrigger>
                <SelectValue placeholder="选择提供商类型" />
              </SelectTrigger>
              <SelectContent>
                {PROVIDER_TYPES.map((type) => (
                  <SelectItem key={type.value} value={type.value}>
                    {type.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Base URL */}
          <div className="space-y-2">
            <label className="text-sm font-medium">Base URL</label>
            <Input
              value={form.base_url}
              onChange={(e) =>
                setForm((prev) => ({ ...prev, base_url: e.target.value }))
              }
              placeholder="https://api.openai.com/v1"
              required
            />
          </div>

          {/* API Key */}
          <div className="space-y-2">
            <label className="text-sm font-medium">
              API Key{' '}
              {isEditing && (
                <span className="text-muted-foreground">(留空则不修改)</span>
              )}
            </label>
            <Input
              type="password"
              value={form.api_key}
              onChange={(e) =>
                setForm((prev) => ({ ...prev, api_key: e.target.value }))
              }
              placeholder={isEditing ? 'sk-...' : 'sk-...'}
              required={!isEditing}
            />
          </div>

          {/* Default toggle */}
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="is_default"
              checked={form.is_default}
              onChange={(e) =>
                setForm((prev) => ({ ...prev, is_default: e.target.checked }))
              }
              className="h-4 w-4 rounded border-input"
            />
            <label htmlFor="is_default" className="text-sm">
              设为默认提供商
            </label>
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
            >
              取消
            </Button>
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              {isEditing ? '保存' : '添加'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
