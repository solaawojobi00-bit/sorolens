import * as matchers from "@testing-library/jest-dom/matchers";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mockGetGlobalStats = vi.fn();
const mockGetWatchdogStats = vi.fn();

vi.mock("@/lib/api", () => ({
  getGlobalStats: (...args: unknown[]) => mockGetGlobalStats(...args),
  getWatchdogStats: (...args: unknown[]) => mockGetWatchdogStats(...args),
}));

expect.extend(matchers);

const GLOBAL = {
  tracked_contracts: 12,
  total_events: 3400,
  total_invocations: 5600,
};
const WATCHDOG = { total_monitored: 7 };

function tile(label: string): HTMLElement {
  return screen.getByText(label).parentElement as HTMLElement;
}

async function renderStats() {
  const { LiveStats } = await import("@/components/LiveStats");
  return render(<LiveStats />);
}

describe("LiveStats", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetGlobalStats.mockResolvedValue(GLOBAL);
    mockGetWatchdogStats.mockResolvedValue(WATCHDOG);
  });

  afterEach(() => {
    cleanup();
  });

  it("renders the counts when both requests succeed", async () => {
    await renderStats();

    await waitFor(() =>
      expect(within(tile("Contracts indexed")).getByText("12")).toBeVisible()
    );
    expect(within(tile("Events tracked")).getByText("3.4K")).toBeVisible();
    expect(within(tile("Contracts monitored")).getByText("7")).toBeVisible();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("renders a real zero as 0, not as an error", async () => {
    mockGetGlobalStats.mockResolvedValue({
      tracked_contracts: 0,
      total_events: 0,
      total_invocations: 0,
    });
    await renderStats();

    await waitFor(() =>
      expect(within(tile("Events tracked")).getByText("0")).toBeVisible()
    );
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows an error and dashes instead of zeros when both requests fail", async () => {
    mockGetGlobalStats.mockRejectedValue(new Error("down"));
    mockGetWatchdogStats.mockRejectedValue(new Error("down"));
    await renderStats();

    await screen.findByText("Couldn't load live stats.");
    for (const label of [
      "Contracts indexed",
      "Events tracked",
      "Invocations traced",
      "Contracts monitored",
    ]) {
      expect(within(tile(label)).getByText("—")).toBeVisible();
      expect(within(tile(label)).queryByText("0")).toBeNull();
    }
  });

  it("only dashes the figures whose request failed", async () => {
    mockGetWatchdogStats.mockRejectedValue(new Error("watchdog down"));
    await renderStats();

    await screen.findByText("Couldn't load live stats.");
    expect(within(tile("Contracts indexed")).getByText("12")).toBeVisible();
    expect(within(tile("Contracts monitored")).getByText("—")).toBeVisible();
  });

  it("retries both requests and recovers", async () => {
    mockGetGlobalStats.mockRejectedValueOnce(new Error("down"));
    await renderStats();

    await screen.findByText("Couldn't load live stats.");
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));

    await waitFor(() =>
      expect(within(tile("Contracts indexed")).getByText("12")).toBeVisible()
    );
    expect(screen.queryByRole("alert")).toBeNull();
    expect(mockGetGlobalStats).toHaveBeenCalledTimes(2);
    expect(mockGetWatchdogStats).toHaveBeenCalledTimes(2);
  });
});
