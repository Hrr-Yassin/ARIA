/* Local component demonstrations only. No APIs, telemetry, credentials or persistence. */
(function () {
  'use strict';
  const root = document.documentElement;
  document.getElementById('density').addEventListener('change', function () {
    root.dataset.density = this.value === 'compact' ? 'compact' : 'comfortable';
  });
  document.getElementById('motion').addEventListener('change', function () {
    root.dataset.motion = this.checked ? 'off' : 'system';
  });
  document.querySelectorAll('[data-token]').forEach(function (button) {
    button.addEventListener('click', function () {
      const token = button.dataset.token;
      const value = getComputedStyle(root).getPropertyValue(token).trim();
      document.getElementById('token-readout').textContent = token + ': ' + value;
    });
  });
})();
