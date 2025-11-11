function usagePercentFromBytes(totalBytes, availableBytes) {
  const total = Number(totalBytes);
  if (!Number.isFinite(total) || total <= 0) {
    return 0;
  }
  const available = Number.isFinite(Number(availableBytes))
    ? Number(availableBytes)
    : 0;
  const clampedAvailable = Math.min(Math.max(available, 0), total);
  const usedRatio = 1 - clampedAvailable / total;
  const pct = usedRatio * 100;
  return Math.min(Math.max(pct, 0), 100);
}

function widthFromBytes(totalBytes, availableBytes) {
  const pct = usagePercentFromBytes(totalBytes, availableBytes);
  return `${pct.toFixed(1)}%`;
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    usagePercentFromBytes,
    widthFromBytes,
  };
}
