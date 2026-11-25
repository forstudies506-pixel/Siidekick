export function SiteHeader() {
  return (
    <header className="site-header">
      <a className="wordmark" href="/" aria-label="Siidekick home">
        Siide<span>kick</span>
      </a>
      <nav aria-label="Primary navigation">
        <a href="/#how">How it works</a>
        <a href="/app">Open dashboard</a>
      </nav>
    </header>
  );
}
