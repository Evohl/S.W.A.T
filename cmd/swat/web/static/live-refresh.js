(() => {
	const container = document.querySelector("[data-live-refresh]");
	if (!container) {
		return;
	}
	const intervalMs = 3000;
	let refreshing = false;

	const shouldPause = () => {
		if (window.swatLiveRefreshPaused) {
			return true;
		}
		const active = document.activeElement;
		if (!active) {
			return false;
		}
		return active.tagName === "INPUT" || active.tagName === "SELECT" || active.tagName === "TEXTAREA";
	};

	const tick = async () => {
		if (refreshing || document.hidden || shouldPause()) {
			return;
		}
		refreshing = true;
		try {
			const response = await fetch(location.href, { headers: { "X-Live-Refresh": "1" } });
			if (!response.ok) {
				return;
			}
			const html = await response.text();
			if (shouldPause()) {
				return;
			}
			const next = new DOMParser().parseFromString(html, "text/html").querySelector("[data-live-refresh]");
			if (!next) {
				return;
			}
			container.innerHTML = next.innerHTML;
			if (typeof window.swatReapplyTranslations === "function") {
				window.swatReapplyTranslations();
			}
			window.dispatchEvent(new CustomEvent("swat:refreshed"));
		} catch (err) {
			/* transient network errors are ignored, next tick retries */
		} finally {
			refreshing = false;
		}
	};

	setInterval(tick, intervalMs);
})();
