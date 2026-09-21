/*
 * The viewer's only script, and the only one the Content-Security-Policy allows: served
 * from this origin, never inline.
 *
 * It does two things, and the page works without both of them:
 *
 *   1. The theme control. It is hidden until this script runs, so a browser without
 *      Javascript never shows a control that would do nothing; the page still follows the
 *      system preference through CSS.
 *   2. The full-window transition for the OAuth2 consent, using Canvas's own
 *      `requestFullWindowLaunch` postMessage rather than a pop-up. If Canvas does not
 *      answer, the form submits normally and the consent is attempted in the iframe.
 */
(function () {
  'use strict';

  var THEME_KEY = 'cmv-theme';

  function readStoredTheme() {
    try {
      return window.localStorage.getItem(THEME_KEY);
    } catch (error) {
      // Storage can be unavailable in a third-party iframe. The system preference stands.
      return null;
    }
  }

  function storeTheme(value) {
    try {
      window.localStorage.setItem(THEME_KEY, value);
    } catch (error) {
      /* The choice simply does not persist. */
    }
  }

  function setUpTheme() {
    var control = document.querySelector('[data-theme-control]');
    var select = document.querySelector('[data-theme-select]');
    if (!control || !select) return;

    var stored = readStoredTheme();
    if (stored === 'light' || stored === 'dark' || stored === 'system') {
      document.documentElement.setAttribute('data-theme', stored);
      select.value = stored;
    }

    control.hidden = false;
    select.addEventListener('change', function () {
      document.documentElement.setAttribute('data-theme', select.value);
      storeTheme(select.value);
    });
  }

  function setUpFullWindow() {
    var form = document.querySelector('[data-full-window]');
    if (!form) return;

    form.addEventListener('submit', function (event) {
      var url = form.getAttribute('data-full-window-url');
      if (!url || window.parent === window) return; // Not framed: submit normally.

      event.preventDefault();
      try {
        window.parent.postMessage(
          {
            subject: 'requestFullWindowLaunch',
            data: {
              url: url,
              placement: form.getAttribute('data-placement') || 'file_menu',
              launchType: 'same_window',
            },
          },
          '*',
        );
      } catch (error) {
        form.submit();
        return;
      }

      // If Canvas does not act on the message, fall back to submitting the form, which
      // attempts the consent inside the iframe.
      window.setTimeout(function () {
        form.submit();
      }, 1200);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      setUpTheme();
      setUpFullWindow();
    });
  } else {
    setUpTheme();
    setUpFullWindow();
  }
})();
