"use client";

import {
  Play,
  Pause,
  Rewind,
  FastForward,
  Volume2,
  Volume1,
  VolumeX,
  Loader2,
  Gauge,
  PanelRightClose,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useAudioPlayer } from "@/hooks/use-audio-player";
import { useAudioStore } from "@/stores/audio-store";
import { formatTimeDisplay } from "@/lib/utils";
import { useMemo, useState, useCallback, useEffect } from "react";

const SPEED_OPTIONS = [0.5, 0.75, 1, 1.25, 1.5, 1.75, 2, 2.5, 3];

interface AudioPlayerProps {
  audioUrl: string;
  title: string;
  podcastName?: string;
  coverUrl?: string;
}

function VolumeIcon({ volume, isMuted }: { volume: number; isMuted: boolean }) {
  if (isMuted || volume === 0) return <VolumeX className="h-4 w-4 text-player-muted" />;
  if (volume < 0.5) return <Volume1 className="h-4 w-4 text-player-muted" />;
  return <Volume2 className="h-4 w-4 text-player-muted" />;
}

function PodcastWave({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
      <path d="M12 1a4 4 0 0 0-4 4v6a4 4 0 0 0 8 0V5a4 4 0 0 0-4-1z" />
      <path d="M19 11a1 1 0 1 0-2 0 5 5 0 0 1-10 0 1 1 0 1 0-2 0 7 7 0 0 0 6 6.93V21h-2a1 1 0 1 0 0 2h6a1 1 0 1 0 0-2h-2v-3.07A7 7 0 0 0 19 11z" />
    </svg>
  );
}

function CoverArt({
  coverUrl,
  isPlaying,
  size = "md",
}: {
  coverUrl?: string;
  isPlaying: boolean;
  size?: "sm" | "md" | "lg";
}) {
  const configs = {
    sm: { outer: "h-10 w-10 rounded-lg", icon: "h-5 w-5", barH: 3, gap: 1 },
    md: { outer: "h-14 w-14 rounded-xl", icon: "h-6 w-6", barH: 4, gap: 1.5 },
    lg: { outer: "h-28 w-28 rounded-2xl shadow-lg", icon: "h-10 w-10", barH: 5, gap: 2 },
  };
  const c = configs[size];

  return (
    <div className={`relative shrink-0 overflow-hidden ${c.outer}`}>
      {coverUrl ? (
        <img src={coverUrl} alt="Cover" className="h-full w-full object-cover" />
      ) : (
        <div className="flex h-full w-full items-center justify-center bg-gradient-to-br from-player-accent/30 to-player-accent/10">
          <PodcastWave className={`${c.icon} text-player-accent`} />
        </div>
      )}
      {isPlaying && (
        <div className="absolute inset-0 flex items-end justify-center bg-black/25" style={{ gap: c.gap, paddingBottom: c.barH + 4 }}>
          <span style={{ width: c.barH, height: c.barH * 2 }} className="rounded-full bg-white/90 animate-[equalizer-1_0.6s_ease-in-out_infinite]" />
          <span style={{ width: c.barH, height: c.barH * 2.5 }} className="rounded-full bg-white/90 animate-[equalizer-2_0.6s_ease-in-out_0.2s_infinite]" />
          <span style={{ width: c.barH, height: c.barH * 1.8 }} className="rounded-full bg-white/90 animate-[equalizer-3_0.6s_ease-in-out_0.4s_infinite]" />
        </div>
      )}
    </div>
  );
}

function ProgressTooltip({ visible, pct, time }: { visible: boolean; pct: number; time: string }) {
  return (
    <div className={`progress-tooltip ${visible ? "visible" : ""}`} style={{ left: `${pct}%` }}>
      {time}
    </div>
  );
}

export function AudioPlayer({ audioUrl, title, podcastName, coverUrl }: AudioPlayerProps) {
  const { audioRef, togglePlay, skip, changeRate, changeVolume, toggleMute } = useAudioPlayer(audioUrl);

  const isPlaying = useAudioStore((s) => s.isPlaying);
  const currentTime = useAudioStore((s) => s.currentTime);
  const duration = useAudioStore((s) => s.duration);
  const buffered = useAudioStore((s) => s.buffered);
  const playbackRate = useAudioStore((s) => s.playbackRate);
  const volume = useAudioStore((s) => s.volume);
  const isMuted = useAudioStore((s) => s.isMuted);
  const isLoading = useAudioStore((s) => s.isLoading);

  const [isOpen, setIsOpen] = useState(false);
  const [tooltipVisible, setTooltipVisible] = useState(false);
  const [tooltipPct, setTooltipPct] = useState(0);
  const [tooltipTime, setTooltipTime] = useState("");

  const playedPct = duration > 0 ? (currentTime / duration) * 100 : 0;
  const bufferedPct = duration > 0 ? (buffered / duration) * 100 : 0;

  const seekTrackStyle = useMemo(
    () => ({
      background: `linear-gradient(to right,
        var(--player-accent) 0%, var(--player-accent) ${playedPct}%,
        var(--player-buffered) ${playedPct}%, var(--player-buffered) ${bufferedPct}%,
        var(--player-track) ${bufferedPct}%, var(--player-track) 100%)`,
    }),
    [playedPct, bufferedPct]
  );

  const volumePct = isMuted ? 0 : volume * 100;
  const volumeTrackStyle = useMemo(
    () => ({
      background: `linear-gradient(to right,
        var(--player-muted) 0%, var(--player-muted) ${volumePct}%,
        var(--player-track) ${volumePct}%, var(--player-track) 100%)`,
    }),
    [volumePct]
  );

  const handleProgressMouseMove = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      const rect = e.currentTarget.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const pct = Math.max(0, Math.min(1, x / rect.width));
      setTooltipPct(pct * 100);
      setTooltipTime(formatTimeDisplay(pct * duration));
      setTooltipVisible(true);
    },
    [duration]
  );

  const handleProgressMouseLeave = useCallback(() => setTooltipVisible(false), []);

  const handleSeek = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const t = parseFloat(e.target.value);
      if (audioRef.current) audioRef.current.currentTime = t;
    },
    [audioRef]
  );

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isOpen) setIsOpen(false);
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [isOpen]);

  if (!audioUrl) return null;

  return (
    <>
      <audio ref={audioRef} preload="metadata" className="hidden" />

      {/* Backdrop */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/30 backdrop-blur-sm transition-opacity dark:bg-black/50"
          onClick={() => setIsOpen(false)}
        />
      )}

      {/* Floating toggle button */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className="fixed bottom-6 right-6 z-50 group"
          aria-label="打开播放器"
        >
          {/* Glow ring */}
          <span className="absolute inset-0 rounded-full opacity-40 group-hover:opacity-60 transition-opacity" style={{
            background: "var(--player-accent)",
            filter: "blur(10px)",
          }} />
          <span className="relative flex h-14 w-14 items-center justify-center rounded-full transition-all group-hover:scale-105 group-active:scale-95" style={{
            background: "linear-gradient(135deg, var(--player-accent), hsl(24 90% 45%))",
            boxShadow: "0 4px 20px hsl(28 85% 50% / 0.5), 0 0 0 2px hsl(28 85% 58% / 0.2)",
          }}>
            {isLoading ? (
              <Loader2 className="h-5 w-5 text-white animate-spin" />
            ) : isPlaying ? (
              <Pause className="h-5 w-5 text-white" />
            ) : (
              <Play className="h-5 w-5 text-white translate-x-[1px]" />
            )}
          </span>
        </button>
      )}

      {/* Right-side drawer */}
      <div
        className={`fixed top-0 right-0 z-50 h-full w-80 flex flex-col border-l transition-transform duration-300 ease-[cubic-bezier(0.16,1,0.3,1)] ${
          isOpen ? "translate-x-0" : "translate-x-full"
        }`}
        style={{
          background: "var(--player-bg)",
          borderColor: "var(--player-track)",
        }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: "var(--player-track)" }}>
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full" style={{ background: isPlaying ? "#22c55e" : "var(--player-muted)" }} />
            <span className="text-xs font-semibold tracking-wide uppercase" style={{ color: "var(--player-fg)", opacity: 0.5 }}>
              {isPlaying ? "正在播放" : "播放器"}
            </span>
          </div>
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 rounded-full hover:bg-white/10"
            style={{ color: "var(--player-muted)" }}
            onClick={() => setIsOpen(false)}
            aria-label="收起播放器"
          >
            <PanelRightClose className="h-4 w-4" />
          </Button>
        </div>

        {/* Cover + info */}
        <div className="flex flex-col items-center px-6 pt-8 pb-6">
          <CoverArt coverUrl={coverUrl} isPlaying={isPlaying} size="lg" />
          <p className="mt-5 text-center text-sm font-semibold leading-snug" style={{ color: "var(--player-fg)" }}>
            {title}
          </p>
          {podcastName && (
            <p className="mt-1 text-center text-xs" style={{ color: "var(--player-muted)" }}>
              {podcastName}
            </p>
          )}
        </div>

        {/* Progress */}
        <div className="relative px-6">
          <div className="relative" onMouseMove={handleProgressMouseMove} onMouseLeave={handleProgressMouseLeave}>
            <input
              type="range"
              className="audio-slider"
              min={0}
              max={duration || 0}
              step={0.1}
              value={currentTime}
              onChange={handleSeek}
              style={seekTrackStyle}
              aria-label="播放进度"
            />
            <div className="mt-2 flex items-center justify-between">
              <span className="text-[11px] font-mono tabular-nums" style={{ color: "var(--player-muted)" }}>
                {formatTimeDisplay(currentTime)}
              </span>
              <span className="text-[11px] font-mono tabular-nums" style={{ color: "var(--player-muted)" }}>
                {formatTimeDisplay(duration)}
              </span>
            </div>
          </div>
          <ProgressTooltip visible={tooltipVisible} pct={tooltipPct} time={tooltipTime} />
        </div>

        {/* Transport controls */}
        <div className="flex items-center justify-center gap-3 px-6 py-5">
          <Button
            variant="ghost"
            size="icon"
            className="h-9 w-9 shrink-0 rounded-full transition-colors hover:bg-white/10"
            style={{ color: "var(--player-muted)" }}
            onClick={() => skip(-15)}
            aria-label="后退15秒"
          >
            <div className="flex flex-col items-center">
              <Rewind className="h-4 w-4" />
              <span className="text-[7px] leading-none opacity-60">15</span>
            </div>
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-9 w-9 shrink-0 rounded-full transition-colors hover:bg-white/10"
            style={{ color: "var(--player-muted)" }}
            onClick={() => skip(-5)}
            aria-label="后退5秒"
          >
            <Rewind className="h-4 w-4" />
          </Button>

          {/* Main play button — larger, bold accent gradient, strong glow */}
          <button
            className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full transition-all active:scale-90"
            style={{
              background: "linear-gradient(135deg, hsl(28 90% 55%), hsl(20 90% 48%))",
              color: "#fff",
              boxShadow: "0 0 0 3px hsl(28 85% 58% / 0.15), 0 6px 24px hsl(28 85% 45% / 0.5)",
            }}
            onClick={togglePlay}
            disabled={isLoading}
            aria-label={isPlaying ? "暂停" : "播放"}
          >
            {isLoading ? (
              <Loader2 className="h-6 w-6 animate-spin" />
            ) : isPlaying ? (
              <Pause className="h-6 w-6" />
            ) : (
              <Play className="h-6 w-6 translate-x-[2px]" />
            )}
          </button>

          <Button
            variant="ghost"
            size="icon"
            className="h-9 w-9 shrink-0 rounded-full transition-colors hover:bg-white/10"
            style={{ color: "var(--player-muted)" }}
            onClick={() => skip(5)}
            aria-label="快进5秒"
          >
            <FastForward className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-9 w-9 shrink-0 rounded-full transition-colors hover:bg-white/10"
            style={{ color: "var(--player-muted)" }}
            onClick={() => skip(15)}
            aria-label="快进15秒"
          >
            <div className="flex flex-col items-center">
              <FastForward className="h-4 w-4" />
              <span className="text-[7px] leading-none opacity-60">15</span>
            </div>
          </Button>
        </div>

        {/* Speed + Volume */}
        <div className="flex flex-col gap-4 border-t px-6 py-4" style={{ borderColor: "var(--player-track)" }}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Gauge className="h-4 w-4" style={{ color: "var(--player-muted)" }} />
              <span className="text-xs" style={{ color: "var(--player-muted)" }}>速度</span>
            </div>
            <Select value={String(playbackRate)} onValueChange={(v) => changeRate(parseFloat(v))}>
              <SelectTrigger
                className="h-7 w-[64px] border-none px-2 text-xs font-semibold"
                style={{ background: "var(--player-track)", color: "var(--player-fg)" }}
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {SPEED_OPTIONS.map((rate) => (
                  <SelectItem key={rate} value={String(rate)}>{rate}x</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center gap-3">
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 shrink-0 rounded-full hover:bg-white/10"
              onClick={toggleMute}
              aria-label={isMuted ? "取消静音" : "静音"}
              style={{ color: "var(--player-muted)" }}
            >
              <VolumeIcon volume={volume} isMuted={isMuted} />
            </Button>
            <input
              type="range"
              className="audio-slider flex-1"
              min={0}
              max={1}
              step={0.01}
              value={isMuted ? 0 : volume}
              onChange={(e) => changeVolume(parseFloat(e.target.value))}
              style={volumeTrackStyle}
              aria-label="音量"
            />
          </div>
        </div>

        {/* Footer hint */}
        <div className="mt-auto px-6 py-3">
          <p className="text-center text-[10px]" style={{ color: "var(--player-muted)", opacity: 0.4 }}>
            Esc 收起
          </p>
        </div>
      </div>
    </>
  );
}
