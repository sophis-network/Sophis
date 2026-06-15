// Sophis Energy Offset Calculator — pure client-side computation.

(function () {
  "use strict";

  const inputs = ["hashrate", "power", "hours", "intensity", "creditprice"];
  const out = {
    energy: document.getElementById("energy-out"),
    co2: document.getElementById("co2-out"),
    cost: document.getElementById("cost-out"),
  };

  const DAYS_PER_MONTH = 30;

  function num(id) {
    const v = parseFloat(document.getElementById(id).value);
    return Number.isFinite(v) ? Math.max(0, v) : 0;
  }

  function fmt(n, digits) {
    if (!Number.isFinite(n)) return "0";
    return n.toLocaleString("en-US", { minimumFractionDigits: digits, maximumFractionDigits: digits });
  }

  function recompute() {
    const power_w = num("power");
    const hours = num("hours");
    const intensity = num("intensity");
    const creditPrice = num("creditprice");

    const kwh = (power_w * hours * DAYS_PER_MONTH) / 1000;
    const co2_kg = (kwh * intensity) / 1000;
    const cost_usd = (co2_kg / 1000) * creditPrice;

    out.energy.textContent = fmt(kwh, 2);
    out.co2.textContent = fmt(co2_kg, 2);
    out.cost.textContent = fmt(cost_usd, 2);
  }

  inputs.forEach(function (id) {
    const el = document.getElementById(id);
    if (el) el.addEventListener("input", recompute);
  });

  recompute();
})();
