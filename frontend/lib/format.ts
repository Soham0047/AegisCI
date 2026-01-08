export function formatDate(value?: string | null): string {
  if (!value) return "unknown";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

export function truncate(value: string, max = 120): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max - 12).trim()}... (truncated)`;
}

export function formatPercent(value: number): string {
  return `${Math.round(value * 100)}%`;
}
