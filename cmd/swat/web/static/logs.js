document.addEventListener("DOMContentLoaded", () => {
	const form = document.querySelector(".log-filters form");
	if (!form) {
		return;
	}

	form.querySelectorAll('input[type="checkbox"]').forEach((checkbox) => {
		checkbox.addEventListener("change", () => form.submit());
	});
});