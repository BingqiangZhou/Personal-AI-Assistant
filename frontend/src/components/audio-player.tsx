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
  ChevronRight,
  ChevronLeft,
  Music,
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
const DRAWER_WIDTH = "w-72 sm:w-80";

interface AudioPlayerProps {
  audioUrl: string;
  title: string;
  podcastName?: string;
  coverUrl?: string;
}

function VolumeIcon({
  volume,
  isMuted,
}: {
  volume: number;
  isMuted: boolean;
}) {
  if (isMuted || volume === 0)
    return <VolumeX className="h-4 w-4 text-player-muted" />;
  if (volume < 0.5)
    return <Volume1 className="h-4 w-4 text-player-muted" />;
  return <Volume2 className="h-4 w-4 text-player-muted" />;
}

function PodcastWave({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="currentColor"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path d="M12 1a4 4 0 0 0-4 4v6a4 4 0 0 0 8 0V5a4 4 0 0 0-4-1z" />
      <path d="M19 11a1 1 0 1 0-2 0 5 5 0 0 1-10 0 1 1 0 1 0-2 0 7 7 0 0 0 6 6.93V21h-2a1 1 0 1 0 0 2h6a1 1 0 1 0 0-2h-2v-3.07A7 7 0 0 0 19 11z" />
    </svg>
  );
}

function CoverThumbnail({
  coverUrl,
  isPlaying,
  size = "md",
}: {
  coverUrl?: string;
  isPlaying: boolean;
  size?: "sm" | "md" | "lg";
}) {
  const sizeClasses = {
    sm: "h-10 w-10",
    md: "h-12 w-12",
    lg: "h-20 w-20",
  };

  return (
    <div className={`relative shrink-0 overflow-hidden rounded-lg ${sizeClasses[size]}`}>
      {coverUrl ? (
        <img
          src={coverUrl}
          alt="Cover"
          className="h-full w-full object-cover"
        />
      ) : (
        <div className="flex h-full w-full items-center justify-center bg-gradient-to-br from-player-accent/20 to-player-accent/5">
          <PodcastWave className={size === "lg" ? "h-8 w-8" : "h-5 w-5"} />
        </div>
      )}
      {isPlaying && (
        <div className="absolute inset-0 flex items-end justify-center gap-[2px] pb-1.5 bg-black/30">
          <span className="w-[3px] rounded-full bg-player-fg animate-[equalizer-1_0.6s_ease-in-out_infinite]" />
          <span className="w-[3px] rounded-full bg-player-fg animate-[equalizer-2_0.6s_ease-in-out_0.2s_infinite]" />
          <span className="w-[3px] rounded-full bg-player-fg animate-[equalizer-3_0.6s_ease-in-out_0.4s_infinite]" />
        </div>
      )}
    </div>
  );
}

function ProgressTooltip({
  visible,
  pct,
  time,
}: {
  visible: boolean;
  pct: number;
  time: string;
}) {
  return (
    <div
      className={`progress-tooltip ${visible ? "visible" : ""}`}
      style={{ left: `${pct}%` }}
    >
      {time}
    </div>
  );
}

export function AudioPlayer({
  audioUrl,
  title,
  podcastName,
  coverUrl,
}: AudioPlayerProps) {
  const {
    audioRef,
    togglePlay,
    skip,
    changeRate,
    changeVolume,
    toggleMute,
  } = useAudioPlayer(audioUrl);

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
      const time = pct * duration;
      setTooltipPct(pct * 100);
      setTooltipTime(formatTimeDisplay(time));
      setTooltipVisible(true);
    },
    [duration]
  );

  const handleProgressMouseLeave = useCallback(() => {
    setTooltipVisible(false);
  }, []);

  const handleSeek = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const t = parseFloat(e.target.value);
      if (audioRef.current) audioRef.current.currentTime = t;
    },
    [audioRef]
  );

  // Close drawer on Escape
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isOpen) setIsOpen(false);
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [isOpen]);

  if (!audioUrl) return null;

  return (
    <>
      <audio ref={audioRef} preload="metadata" className="hidden" />

      {/* Backdrop overlay when drawer is open */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/20 backdrop-blur-sm transition-opacity dark:bg-black/40"
          onClick={() => setIsOpen(false)}
        />
      )}

      {/* Floating toggle button (visible when drawer is closed) */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          className="fixed bottom-6 right-6 z-50 flex h-14 w-14 items-center justify-center rounded-full shadow-xl transition-all hover:scale-105 active:scale-95"
          style={{
            background: "var(--player-bg)",
            border: "1px solid var(--player-track)",
            boxShadow: "0 4px 24px hsl(20 10% 0% / 0.2)",
          }}
          aria-label="打开播放器"
        >
          <CoverThumbnail coverUrl={coverUrl} isPlaying={isPlaying} size="sm" />
        </button>
      )}

      {/* Right-side drawer panel */}
      <div
        className={`fixed top-0 right-0 z-50 h-full ${DRAWER_WIDTH} flex flex-col border-l transition-transform duration-300 ease-[cubic-bezier(0.16,1,0.3,1)] ${
          isOpen ? "translate-x-0" : "translate-x-full"
        }`}
        style={{ background: "var(--player-bg)" }}
      >
        {/* Drawer header: close button */}
        <div className="flex items-center justify-between border-b border-player-track px-4 py-3">
          <span className="text-xs font-medium uppercase tracking-wider text-player-muted">
            播放器
          </span>
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 rounded-full text-player-muted hover:bg-white/10 hover:text-player-fg"
            onClick={() => setIsOpen(false)}
            aria-label="收起播放器"
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>

        {/* Cover art (large) */}
        <div className="flex flex-col items-center px-6 pt-6 pb-4">
          <CoverThumbnail coverUrl={coverUrl} isPlaying={isPlaying} size="lg" />
          <p className="mt-4 text-center text-sm font-medium leading-snug text-player-fg">
            {title}
          </p>
          {podcastName && (
            <p className="mt-1 text-center text-xs text-player-muted">
              {podcastName}
            </p>
          )}
          {isPlaying && (
            <div className="mt-2 flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-green-500 animate-pulse" />
              <span className="text-[10px] text-player-fg/70">播放中</span>
            </div>
          )}
        </div>

        {/* Progress bar */}
        <div className="relative px-6">
          <div
            className="relative"
            onMouseMove={handleProgressMouseMove}
            onMouseLeave={handleProgressMouseLeave}
          >
            <div className="mb-1 flex items-center justify-between">
              <span className="text-[11px] font-mono tabular-nums text-player-muted">
                {formatTimeDisplay(currentTime)}
              </span>
              <span className="text-[11px] font-mono tabular-nums text-player-muted">
                {formatTimeDisplay(duration)}
              </span>
            </div>
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
          </div>
          <ProgressTooltip
            visible={tooltipVisible}
            pct={tooltipPct}
            time={tooltipTime}
          />
        </div>

        {/* Transport controls */}
        <div className="flex items-center justify-center gap-2 px-6 py-4">
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 shrink-0 rounded-full text-player-muted transition-colors hover:bg-white/10 hover:text-player-fg"
            onClick={() => skip(-15)}
            aria-label="后退15秒"
          >
            <div className="flex flex-col items-center">
              <Rewind className="h-3.5 w-3.5" />
              <span className="mt-0.5 text-[7px] leading-none">15</span>
            </div>
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 shrink-0 rounded-full text-player-muted transition-colors hover:bg-white/10 hover:text-player-fg"
            onClick={() => skip(-5)}
            aria-label="后退5秒"
          >
            <Rewind className="h-3.5 w-3.5" />
          </Button>
          <Button
            className="h-11 w-11 shrink-0 rounded-full border-0 shadow-lg transition-transform active:scale-95"
            style={{
              background: "var(--player-accent)",
              color: "var(--player-bg)",
              boxShadow: "0 4px 20px hsl(28 85% 40% / 0.4)",
            }}
            onClick={togglePlay}
            disabled={isLoading}
            aria-label={isPlaying ? "暂停" : "播放"}
          >
            {isLoading ? (
              <Loader2 className="h-5 w-5 animate-spin" />
            ) : isPlaying ? (
              <Pause className="h-5 w-5" />
            ) : (
              <Play className="h-5 w-5 translate-x-[2px]" />
            )}
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 shrink-0 rounded-full text-player-muted transition-colors hover:bg-white/10 hover:text-player-fg"
            onClick={() => skip(5)}
            aria-label="快进5秒"
          >
            <FastForward className="h-3.5 w-3.5" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 shrink-0 rounded-full text-player-muted transition-colors hover:bg-white/10 hover:text-player-fg"
            onClick={() => skip(15)}
            aria-label="快进15秒"
          >
            <div className="flex flex-col items-center">
              <FastForward className="h-3.5 w-3.5" />
              <span className="mt-0.5 text-[7px] leading-none">15</span>
            </div>
          </Button>
        </div>

        {/* Speed + Volume */}
        <div className="flex flex-col gap-3 border-t border-player-track px-6 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <Gauge className="h-3.5 w-3.5 text-player-muted" />
              <span className="text-[10px] text-player-muted">速度</span>
            </div>
            <Select
              value={String(playbackRate)}
              onValueChange={(v) => changeRate(parseFloat(v))}
            >
              <SelectTrigger
                className="h-6 w-[60px] border-none px-1.5 text-[11px] font-medium text-player-fg/70 hover:text-player-fg"
                style={{ background: "transparent" }}
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {SPEED_OPTIONS.map((rate) => (
                  <SelectItem key={rate} value={String(rate)}>
                    {rate}x
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7 shrink-0 rounded-full"
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

        {/* Keyboard shortcut hint */}
        <div className="mt-auto border-t border-player-track px-6 py-3">
          <p className="text-center text-[10px] text-player-muted/50">
            按 Esc 收起播放器
          </p>
        </div>
      </div>
    </>
  );
}
