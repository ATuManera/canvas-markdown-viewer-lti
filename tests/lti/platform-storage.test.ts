import { describe, expect, it } from 'vitest';
import {
  renderLaunchVerification,
  renderLoginRelay,
  storageKeyFor,
  usesPlatformStorage,
} from '../../src/lti/platform-storage.ts';
import { escapeHtml, jsonForScript } from '../../src/web/html.ts';

const AUTH_ORIGIN = 'https://sso.canvaslms.com';

describe('storage key', () => {
  it('embeds the value, as Canvas recommends, so launches cannot collide', () => {
    expect(storageKeyFor('abc123')).toBe('state-abc123');
    expect(storageKeyFor('abc123')).not.toBe(storageKeyFor('abc124'));
  });
});

describe('usesPlatformStorage', () => {
  it('is off when Canvas sends no lti_storage_target', () => {
    expect(usesPlatformStorage(undefined)).toBe(false);
    expect(usesPlatformStorage('')).toBe(false);
  });

  it('is on for the default _parent and for a named frame', () => {
    expect(usesPlatformStorage('_parent')).toBe(true);
    expect(usesPlatformStorage('post_message_forwarding')).toBe(true);
  });
});

describe('renderLoginRelay', () => {
  const html = renderLoginRelay({
    state: 'state-value-1',
    storageTarget: 'post_message_forwarding',
    authorizationOrigin: AUTH_ORIGIN,
    redirectUrl: 'https://canvas.test.edu/api/lti/authorize_redirect?client_id=1',
    texts: { title: 'Conectando…', continueLabel: 'Continuar' },
    locale: 'es',
  });

  it('stores the state under the recommended key', () => {
    expect(html).toContain('lti.put_data');
    expect(html).toContain('state-state-value-1');
  });

  it('targets the frame Canvas named', () => {
    expect(html).toContain('post_message_forwarding');
  });

  it('sends the message to the OIDC authorization origin, not the Canvas domain', () => {
    expect(html).toContain(AUTH_ORIGIN);
  });

  it('continues to the platform once the state is stored', () => {
    expect(html).toContain('authorize_redirect');
    expect(html).toContain('window.location.replace');
  });

  it('retries against the parent window, as Canvas documents for the RCE case', () => {
    expect(html).toContain("send(window.parent, '*')");
  });

  it('continues even when storage never answers', () => {
    expect(html).toContain('setTimeout(go, config.timeout)');
  });

  it('offers a link for a browser without Javascript', () => {
    expect(html).toContain('<noscript>');
    expect(html).toContain('Continuar');
  });

  it('asks the browser not to send a referrer', () => {
    expect(html).toContain('name="referrer" content="no-referrer"');
  });

  it('declares the page language', () => {
    expect(html).toContain('<html lang="es">');
  });
});

describe('renderLaunchVerification', () => {
  const html = renderLaunchVerification({
    state: 'state-value-1',
    storageTarget: '_parent',
    authorizationOrigin: AUTH_ORIGIN,
    continueUrl: '/lti/launch/continue',
    launchHandle: 'handle-1',
    texts: {
      title: 'Comprobando',
      checking: 'Comprobando el lanzamiento…',
      mismatch: 'No se pudo verificar este lanzamiento.',
      continueLabel: 'Continuar',
    },
    locale: 'es',
  });

  it('reads the stored state back', () => {
    expect(html).toContain('lti.get_data');
    expect(html).toContain('state-state-value-1');
  });

  it('posts the verdict rather than putting it in a URL', () => {
    expect(html).toContain('method="post"');
    expect(html).toContain('name="storage_verified"');
    expect(html).toContain('action="/lti/launch/continue"');
  });

  it('carries the launch handle in a hidden field', () => {
    expect(html).toContain('name="launch" value="handle-1"');
  });

  it('stops and explains when the stored value disagrees', () => {
    expect(html).toContain('No se pudo verificar este lanzamiento.');
    expect(html).toContain('function fail()');
  });

  it('continues when nothing was stored, which is not the same as a mismatch', () => {
    expect(html).toContain("proceed('unavailable')");
    expect(html).toContain("proceed('match')");
  });
});

describe('escaping in the relay pages', () => {
  it('escapes a hostile state into the script without breaking out of it', () => {
    const html = renderLoginRelay({
      state: '</script><img src=x onerror=alert(1)>',
      storageTarget: '_parent',
      authorizationOrigin: AUTH_ORIGIN,
      redirectUrl: 'https://canvas.test.edu/api/lti/authorize_redirect',
      texts: { title: 'x', continueLabel: 'y' },
      locale: 'es',
    });

    expect(html).not.toContain('</script><img');
    expect(html).toContain('\\u003c/script\\u003e');
  });

  it('escapes a hostile continue URL in the form action', () => {
    const html = renderLaunchVerification({
      state: 's',
      storageTarget: '_parent',
      authorizationOrigin: AUTH_ORIGIN,
      continueUrl: '/continue"><script>alert(1)</script>',
      launchHandle: 'h',
      texts: { title: 't', checking: 'c', mismatch: 'm', continueLabel: 'l' },
      locale: 'es',
    });

    expect(html).not.toContain('"><script>alert(1)');
    expect(html).toContain('&quot;&gt;&lt;script&gt;');
  });

  it('escapes a hostile launch handle', () => {
    const html = renderLaunchVerification({
      state: 's',
      storageTarget: '_parent',
      authorizationOrigin: AUTH_ORIGIN,
      continueUrl: '/continue',
      launchHandle: '" autofocus onfocus="alert(1)',
      texts: { title: 't', checking: 'c', mismatch: 'm', continueLabel: 'l' },
      locale: 'es',
    });

    expect(html).not.toContain('onfocus="alert(1)"');
    expect(html).toContain('&quot; autofocus onfocus=&quot;');
  });
});

describe('escapeHtml', () => {
  it('escapes every character that changes meaning in markup', () => {
    expect(escapeHtml('<a href="x">&\'</a>')).toBe(
      '&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;',
    );
  });

  it('is safe inside a single-quoted attribute too', () => {
    expect(escapeHtml("' onload='alert(1)")).not.toContain("'");
  });

  it('handles values that are not strings', () => {
    expect(escapeHtml(42)).toBe('42');
    expect(escapeHtml(null)).toBe('null');
    expect(escapeHtml(undefined)).toBe('undefined');
  });
});

describe('jsonForScript', () => {
  it('neutralises a closing script tag', () => {
    expect(jsonForScript('</script>')).not.toContain('</script>');
  });

  it('round-trips through JSON.parse unchanged', () => {
    const value = { a: '</script>', b: '<>&', c: 'línea\u2028partida' };
    expect(JSON.parse(jsonForScript(value))).toEqual(value);
  });

  it('escapes the Javascript line terminators JSON allows raw', () => {
    expect(jsonForScript('a\u2028b')).toContain('\\u2028');
    expect(jsonForScript('a\u2029b')).toContain('\\u2029');
  });

  it('escapes ampersands so the value cannot start an HTML entity', () => {
    expect(jsonForScript('&lt;')).toContain('\\u0026');
  });

  it('renders undefined as null rather than emitting invalid Javascript', () => {
    expect(jsonForScript(undefined)).toBe('null');
  });
});
