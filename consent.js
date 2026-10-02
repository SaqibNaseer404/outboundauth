(function () {
  var KEY = 'oa-consent';
  function grant() {
    if (typeof gtag === 'function') {
      gtag('consent', 'update', {
        ad_storage: 'granted',
        ad_user_data: 'granted',
        ad_personalization: 'granted',
        analytics_storage: 'granted'
      });
    }
  }
  var choice = null;
  try { choice = localStorage.getItem(KEY); } catch (e) {}
  if (choice === 'granted') { grant(); return; }
  if (choice === 'declined') { return; }
  var banner = document.getElementById('cookie-banner');
  if (!banner) return;
  banner.hidden = false;
  document.getElementById('cookie-accept').addEventListener('click', function () {
    try { localStorage.setItem(KEY, 'granted'); } catch (e) {}
    grant();
    banner.hidden = true;
  });
  document.getElementById('cookie-decline').addEventListener('click', function () {
    try { localStorage.setItem(KEY, 'declined'); } catch (e) {}
    banner.hidden = true;
  });
})();
